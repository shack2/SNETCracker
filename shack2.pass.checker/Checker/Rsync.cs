using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Rsync 弱口令检测：自实现 rsync 守护协议模块认证（端口 873）。
    /// 流程：连接A列模块（空行 → 模块列表 → @RSYNCD: EXIT）→ 连接B按第一个模块认证：
    /// "@RSYNCD: AUTHREQD &lt;challenge&gt;" → 回 "user base64nopad(HASH(password+challenge))" →
    /// "@RSYNCD: OK" 成功 / "@ERROR: auth failed" 口令错误；模块免认证直接判开放。
    /// 协议 32+ 服务端问候行带摘要列表（如 "32.0 sha512 sha256 sha1 md5 md4"），
    /// 客户端应答版本行必须回选一种摘要（源码 compat.c negotiate_daemon_auth）；
    /// 哈希拼接无空格、base64 无填充（authenticate.c generate_hash）。
    /// 列表被禁（list=no）时按常见模块名逐个探测。
    /// </summary>
    class Rsync : CheckerBase
    {
        /// <summary>list=no 时的候选模块名。</summary>
        private static readonly string[] FallbackModules = { "data", "backup", "public", "ftp", "www", "share" };

        /// <summary>服务端问候行解析结果：版本 + 摘要选择。</summary>
        private sealed class Greeting
        {
            public string Version = "";
            public string Digest = "md5";   // 协商出的摘要名（回告服务端 + 实际计算用）
            public bool HasDigestList;      // 服务端是否携带摘要列表（协议 32+）
        }

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }

            // 连接A：取模块列表（服务可能禁列，失败不致命）
            List<string> modules = ListModules(ip, port, timeOut);
            if (modules.Count == 0)
            {
                modules.AddRange(FallbackModules);
            }

            // 连接B：逐个模块尝试进入认证流程（Unknown module 换下一个）
            Exception lastError = null;
            foreach (string module in modules)
            {
                try
                {
                    return TryModule(ip, port, timeOut, module, username, password, server);
                }
                catch (UnknownModuleException)
                {
                    continue;
                }
                catch (Exception e)
                {
                    lastError = e;
                    break;
                }
            }
            if (lastError != null)
            {
                throw lastError;
            }
            throw new Exception("rsync 无可认证模块（全部 Unknown module）");
        }

        private sealed class UnknownModuleException : Exception
        {
            public UnknownModuleException(string msg) : base(msg) { }
        }

        /// <summary>列模块；服务禁列或失败返回空列表。</summary>
        private static List<string> ListModules(string ip, int port, int timeOut)
        {
            var modules = new List<string>();
            try
            {
                using (TextProto tp = new TextProto())
                {
                    tp.Connect(ip, port, timeOut, false);
                    Greeting g = ReadGreeting(tp);
                    tp.SendLine(VersionReply(g));
                    tp.SendLine(""); // 空行 = 请求模块列表
                    while (true)
                    {
                        string line = tp.ReadLine();
                        if (line.StartsWith("@RSYNCD: EXIT", StringComparison.Ordinal))
                        {
                            break;
                        }
                        if (line.Length == 0 || line.StartsWith("@", StringComparison.Ordinal))
                        {
                            continue; // MOTD / 其他控制行
                        }
                        int sp = line.IndexOfAny(new[] { ' ', '\t' });
                        modules.Add(sp > 0 ? line.Substring(0, sp) : line);
                    }
                }
            }
            catch { }
            return modules;
        }

        /// <summary>对指定模块执行一次认证。</summary>
        private static Server TryModule(string ip, int port, int timeOut, string module, string username, string password, Server server)
        {
            using (TextProto tp = new TextProto())
            {
                tp.Connect(ip, port, timeOut, false);
                Greeting g = ReadGreeting(tp);
                server.banner = "@RSYNCD: " + g.Version;
                tp.SendLine(VersionReply(g));
                tp.SendLine(module);

                string line = tp.ReadLine();
                if (line.StartsWith("@RSYNCD: OK", StringComparison.Ordinal))
                {
                    server.isSuccess = true; // 模块免认证
                    server.banner += " 模块[" + module + "]（无认证，开放访问）";
                    return server;
                }
                if (line.StartsWith("@ERROR", StringComparison.Ordinal))
                {
                    if (line.IndexOf("Unknown module", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        throw new UnknownModuleException(line);
                    }
                    throw new Exception("rsync 模块[" + module + "]拒绝: " + line);
                }
                if (!line.StartsWith("@RSYNCD: AUTHREQD", StringComparison.Ordinal))
                {
                    throw new InvalidDataException("非法 rsync 应答: " + line);
                }

                // 认证：base64无填充(HASH(password + challenge))（authenticate.c generate_hash，无空格分隔）
                string challenge = line.Substring("@RSYNCD: AUTHREQD".Length).Trim();
                string digest = ComputeDigest(g.Digest, password, challenge);
                tp.SendLine(username + " " + digest);
                string result = tp.ReadLine();
                if (result.StartsWith("@RSYNCD: OK", StringComparison.Ordinal))
                {
                    server.isSuccess = true;
                    server.banner += " 模块[" + module + "]";
                }
                else if (result.StartsWith("@ERROR", StringComparison.Ordinal)
                    && result.IndexOf("auth failed", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    // 口令错误，正常失败
                }
                else
                {
                    throw new InvalidDataException("非法 rsync 认证应答: " + result);
                }
                return server;
            }
        }

        /// <summary>读服务端问候行并协商摘要：优先 md5（所有构建都支持），其次 sha1/sha256/sha512。</summary>
        private static Greeting ReadGreeting(TextProto tp)
        {
            string greeting = tp.ReadLine();
            if (!greeting.StartsWith("@RSYNCD:", StringComparison.Ordinal))
            {
                throw new InvalidDataException("非 rsync 守护服务: " + greeting);
            }
            string rest = greeting.Substring(8).Trim();
            var g = new Greeting();
            int sp = rest.IndexOf(' ');
            if (sp > 0) // 协议 32+：版本 + 摘要列表
            {
                g.Version = rest.Substring(0, sp);
                g.HasDigestList = true;
                string list = rest.Substring(sp + 1);
                g.Digest = FirstSupported(list);
                if (g.Digest.Length == 0)
                {
                    throw new Exception("rsync 服务端摘要列表无可用算法: " + list);
                }
            }
            else
            {
                g.Version = rest;
                // 无摘要列表：协议 ≥30 默认 md5（compat.c negotiate_daemon_auth）
                if (!g.Version.StartsWith("3", StringComparison.Ordinal))
                {
                    throw new Exception("rsync 协议版本过旧（默认 md4，未实现）: " + g.Version);
                }
            }
            return g;
        }

        private static string FirstSupported(string list)
        {
            foreach (string want in new[] { "md5", "sha1", "sha256", "sha512" })
            {
                if (ListHas(list, want))
                {
                    return want;
                }
            }
            return "";
        }

        private static bool ListHas(string list, string name)
        {
            return (" " + list + " ").IndexOf(" " + name + " ", StringComparison.Ordinal) >= 0;
        }

        /// <summary>版本应答行：服务端带摘要列表时必须回选一种（协议 32+ 强制）。</summary>
        private static string VersionReply(Greeting g)
        {
            return g.HasDigestList ? "@RSYNCD: " + g.Version + " " + g.Digest : "@RSYNCD: " + g.Version;
        }

        /// <summary>base64（去填充）(HASH(password + challenge))。</summary>
        internal static string ComputeDigest(string digestName, string password, string challenge)
        {
            byte[] input = Encoding.UTF8.GetBytes(password + challenge);
            byte[] hash;
            using (HashAlgorithm algo = CreateHash(digestName))
            {
                hash = algo.ComputeHash(input);
            }
            return Convert.ToBase64String(hash).TrimEnd('=');
        }

        private static HashAlgorithm CreateHash(string name)
        {
            switch (name)
            {
                case "sha1": return SHA1.Create();
                case "sha256": return SHA256.Create();
                case "sha512": return SHA512.Create();
                default: return MD5.Create();
            }
        }
    }
}
