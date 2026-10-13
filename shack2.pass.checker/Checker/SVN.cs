using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// SVN（svnserve，svn://）弱口令检测：自实现握手 + CRAM-MD5 认证（RFC 2222 / svn 协议 v2）。
    /// 流程：读服务端能力元组 → 回客户端能力 → 读服务端 mech 列表；
    /// mech 含 ANONYMOUS → 开放访问成功；含 CRAM-MD5 → 挑战应答（HMAC-MD5）。
    /// 口令错误服务端回 failure，属干净失败。
    /// </summary>
    class SVN : CheckerBase
    {
        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }

            using (Socket sock = Sock.Connect(ip, port, timeOut))
            {
                NetworkStream ns = new NetworkStream(sock, false);
                SvnItem greeting = ReadItem(ns); // ( success ( 2 2 ( ...) ( capabilities... ) ) )
                _ = greeting;

                // 客户端能力应答：( 2 2 ( ) ( ) svn://ip/ )
                Send(ns, "( 2 2 ( ) ( ) svn://" + ip + "/ ) ");

                SvnItem authReq = ReadItem(ns); // ( success ( ( MECH... ) realm ) )
                string mechs = authReq != null ? authReq.CollectAtoms() : "";

                if (mechs.IndexOf("ANONYMOUS", StringComparison.OrdinalIgnoreCase) >= 0
                    && mechs.IndexOf("CRAM-MD5", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    Send(ns, "( ANONYMOUS ( ) ) ");
                    server.isSuccess = true;
                    server.banner = "svnserve（匿名开放访问）";
                    return server;
                }

                if (mechs.IndexOf("CRAM-MD5", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    throw new Exception("svnserve 不支持 CRAM-MD5 认证，mechs=" + mechs);
                }

                Send(ns, "( CRAM-MD5 ( ) ) ");
                SvnItem step = ReadItem(ns); // ( step ( "<base64 challenge>" ) )
                string challengeB64 = step != null ? step.FirstString() : null;
                if (challengeB64 == null)
                {
                    throw new InvalidDataException("svnserve 挑战格式异常");
                }

                byte[] challenge = Convert.FromBase64String(challengeB64);
                byte[] pwdBytes = Encoding.UTF8.GetBytes(password);
                string digest;
                using (HMACMD5 hmac = new HMACMD5(pwdBytes))
                {
                    digest = Bin.ToHexLower(hmac.ComputeHash(challenge));
                }
                string token = Convert.ToBase64String(Encoding.UTF8.GetBytes(username + " " + digest));
                Send(ns, "( response ( \"" + token + "\" ) ) ");

                SvnItem result = ReadItem(ns);
                string head = result != null ? result.Head() : "";
                if ("success".Equals(head, StringComparison.OrdinalIgnoreCase))
                {
                    server.isSuccess = true;
                    server.banner = "svnserve CRAM-MD5";
                }
                else if ("failure".Equals(head, StringComparison.OrdinalIgnoreCase))
                {
                    server.isSuccess = false; // 口令错误：干净失败
                }
                else
                {
                    throw new InvalidDataException("svnserve 应答异常: " + head);
                }
            }
            return server;
        }

        // ===================== svnserve 元组协议（项解析） =====================

        private sealed class SvnItem
        {
            public string Atom;            // 原子 / 字符串 / 数字内容
            public System.Collections.Generic.List<SvnItem> Children;

            public string Head()
            {
                if (Children != null && Children.Count > 0)
                {
                    return Children[0].Atom ?? "";
                }
                return Atom ?? "";
            }

            /// <summary>递归收集全部原子（用于提取 mech 列表）。</summary>
            public string CollectAtoms()
            {
                var sb = new StringBuilder();
                CollectInto(sb);
                return sb.ToString();
            }

            private void CollectInto(StringBuilder sb)
            {
                if (Atom != null)
                {
                    sb.Append(Atom).Append(' ');
                }
                if (Children != null)
                {
                    foreach (SvnItem c in Children)
                    {
                        c.CollectInto(sb);
                    }
                }
            }

            /// <summary>找第一个带引号字符串（挑战值）。</summary>
            public string FirstString()
            {
                if (IsQuoted)
                {
                    return Atom;
                }
                if (Children != null)
                {
                    foreach (SvnItem c in Children)
                    {
                        string s = c.FirstString();
                        if (s != null)
                        {
                            return s;
                        }
                    }
                }
                return null;
            }

            public bool IsQuoted;
        }

        private static SvnItem ReadItem(NetworkStream ns)
        {
            // 项可能分多个 TCP 段到达：增量解析，括号配平即完整
            var buf = new MemoryStream();
            byte[] chunk = new byte[1024];
            int depth = 0;
            bool started = false;
            while (true)
            {
                int n = ns.Read(chunk, 0, chunk.Length);
                if (n <= 0)
                {
                    if (!started)
                    {
                        throw new EndOfStreamException("连接被远端关闭");
                    }
                    break; // 服务端半关闭：尝试解析已有数据
                }
                buf.Write(chunk, 0, n);
                foreach (byte b in chunk.AsSpan(0, n).ToArray())
                {
                    if (b == (byte)'(')
                    {
                        depth++;
                        started = true;
                    }
                    else if (b == (byte)')')
                    {
                        depth--;
                    }
                }
                if (started && depth == 0)
                {
                    break;
                }
            }
            string text = Encoding.UTF8.GetString(buf.ToArray());
            int pos = 0;
            return ParseItem(text, ref pos);
        }

        private static SvnItem ParseItem(string s, ref int pos)
        {
            SkipWs(s, ref pos);
            if (pos >= s.Length)
            {
                return null;
            }
            if (s[pos] == '(')
            {
                pos++;
                var list = new SvnItem { Children = new System.Collections.Generic.List<SvnItem>() };
                while (true)
                {
                    SkipWs(s, ref pos);
                    if (pos >= s.Length || s[pos] == ')')
                    {
                        pos++;
                        break;
                    }
                    SvnItem child = ParseItem(s, ref pos);
                    if (child != null)
                    {
                        list.Children.Add(child);
                    }
                }
                return list;
            }
            if (s[pos] == '"')
            {
                pos++;
                int start = pos;
                while (pos < s.Length && s[pos] != '"')
                {
                    pos++;
                }
                string str = s.Substring(start, pos - start);
                pos++;
                return new SvnItem { Atom = str, IsQuoted = true };
            }
            // 原子 / 数字（可能带 "len:" 前缀的字面量，此处按空白切分即可满足认证流程）
            int st = pos;
            while (pos < s.Length && !char.IsWhiteSpace(s[pos]) && s[pos] != '(' && s[pos] != ')')
            {
                pos++;
            }
            return new SvnItem { Atom = s.Substring(st, pos - st) };
        }

        private static void SkipWs(string s, ref int pos)
        {
            while (pos < s.Length && char.IsWhiteSpace(s[pos]))
            {
                pos++;
            }
        }

        private static void Send(NetworkStream ns, string text)
        {
            byte[] b = Encoding.UTF8.GetBytes(text);
            ns.Write(b, 0, b.Length);
            ns.Flush();
        }


    }
}
