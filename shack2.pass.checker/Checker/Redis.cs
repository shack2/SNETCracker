using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Redis 弱口令检测：自实现 RESP 协议（AUTH / PING / INFO），
    /// 替代 StackExchange.Redis（约 2.1 MB IL + System.Configuration.ConfigurationManager）。
    /// 兼容 Redis 6+ ACL（AUTH user pass）与旧版单密码（AUTH pass）。
    /// 实现 IReusableAuth：AUTH 失败连接保持，同一连接可连续尝试整个字典。
    /// </summary>
    class Redis : CheckerBase, IReusableAuth
    {
        private TextProto tp;
        private string banner = "Redis";
        private bool authedOnce; // 已成功过：下次 TryAuth 返回 Closed 强制重连（避免已认证态误报）

        public Redis()
        {

        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            using (TextProto tp = new TextProto())
            {
                tp.Connect(ip, port, timeOut, false);

                bool authed;
                if ("空".Equals(password))
                {
                    // 未授权探测：直接 PING，通即未启用认证
                    authed = PingProbe(tp);
                }
                else if (!string.IsNullOrEmpty(username))
                {
                    authed = AuthOnce(tp, username, password);
                }
                else
                {
                    // 用户名留空：先试 ACL default 用户，再试旧版单密码
                    authed = AuthOnce(tp, "default", password) || AuthOnce(tp, null, password);
                }

                if (authed)
                {
                    server.isSuccess = true;
                    server.banner = ReadVersion(tp);
                }
            }
            return server;
        }

        // ===================== IReusableAuth（批次连接复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            tp = new TextProto();
            tp.Connect(ip, port, timeoutSec, false);
            authedOnce = false;
            banner = "Redis";
        }

        public string Banner
        {
            get { return banner; }
        }

        public AuthResult TryAuth(string user, string password)
        {
            if (authedOnce)
            {
                return AuthResult.Closed; // 已成功：强制新连接，保证下一账号在干净会话上认证
            }
            try
            {
                bool authed;
                if (password.Length == 0)
                {
                    authed = PingProbe(tp);
                }
                else if (!string.IsNullOrEmpty(user))
                {
                    authed = AuthOnce(tp, user, password);
                }
                else
                {
                    authed = AuthOnce(tp, "default", password) || AuthOnce(tp, null, password);
                }
                if (authed)
                {
                    authedOnce = true;
                    banner = ReadVersion(tp);
                    return AuthResult.Success;
                }
                return AuthResult.Failed;
            }
            catch (EndOfStreamException) { return AuthResult.Closed; }
            catch (IOException) { return AuthResult.Closed; }
            catch (SocketException) { return AuthResult.Closed; }
        }

        public void Dispose()
        {
            try { tp?.Dispose(); } catch { }
            tp = null;
        }

        // ===================== 协议实现 =====================

        /// <summary>未授权探测：直接 PING，通即未启用认证。</summary>
        private static bool PingProbe(TextProto tp)
        {
            SendCommand(tp, "PING");
            char type = ReadReply(tp, out string val, out bool isErr);
            return type == '+' && val.Equals("PONG", StringComparison.OrdinalIgnoreCase);
        }

        private static bool AuthOnce(TextProto tp, string user, string password)
        {
            if (user == null)
            {
                SendCommand(tp, "AUTH", password);
            }
            else
            {
                SendCommand(tp, "AUTH", user, password);
            }
            ReadReply(tp, out string val, out bool isErr);
            if (!isErr)
            {
                return true;
            }
            // 服务端未设密码时 AUTH 报这个错 —— 等于任意密码可进，判成功
            return val.IndexOf("no password is set", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string ReadVersion(TextProto tp)
        {
            try
            {
                SendCommand(tp, "INFO", "server");
                char type = ReadReply(tp, out string val, out bool isErr);
                if (!isErr && type == '$')
                {
                    foreach (string line in val.Split('\n'))
                    {
                        if (line.StartsWith("redis_version:", StringComparison.Ordinal))
                        {
                            return "Redis " + line.Substring(14).Trim();
                        }
                    }
                }
            }
            catch { }
            return "Redis";
        }

        /// <summary>发送 RESP 数组命令。</summary>
        private static void SendCommand(TextProto tp, params string[] args)
        {
            var sb = new StringBuilder();
            sb.Append('*').Append(args.Length).Append("\r\n");
            foreach (string a in args)
            {
                int len = Encoding.UTF8.GetByteCount(a);
                sb.Append('$').Append(len).Append("\r\n").Append(a).Append("\r\n");
            }
            tp.SendRaw(sb.ToString());
        }

        /// <summary>
        /// 读一条 RESP 应答。type: + 简单字符串 / - 错误 / : 整数 / $ bulk / * 数组（只读行计数）。
        /// </summary>
        private static char ReadReply(TextProto tp, out string value, out bool isError)
        {
            string head = tp.ReadLine();
            if (head.Length == 0)
            {
                throw new System.IO.InvalidDataException("空 RESP 应答");
            }
            char type = head[0];
            string rest = head.Substring(1);
            isError = type == '-';
            value = rest;
            if (type == '$')
            {
                int len = int.Parse(rest, System.Globalization.CultureInfo.InvariantCulture);
                if (len < 0)
                {
                    value = "";
                }
                else
                {
                    value = Encoding.UTF8.GetString(tp.ReadBytes(len));
                    tp.ReadCrlf();
                }
            }
            return type;
        }
    }
}
