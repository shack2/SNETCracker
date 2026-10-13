using System;
using System.IO;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// POP3 弱口令检测：自实现 USER/PASS，替代 MailKit。
    /// 保留 coremail「weak 提示也算成功」兼容逻辑。
    /// 实现 IReusableAuth：认证失败（-ERR）连接保持，同一连接可连续 USER/PASS。
    /// </summary>
    class POP3 : CheckerBase, IReusableAuth
    {
        private readonly bool useSsl;
        private TextProto tp;
        private string banner = "POP3";
        private bool authedOnce; // 成功后进入 TRANSACTION 态：下次 TryAuth 返回 Closed 强制重连

        public POP3()
        {
            useSsl = false;
        }

        protected POP3(bool useSsl)
        {
            this.useSsl = useSsl;
        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            return Pop3Core.Run(ip, port, username, password, timeOut, useSsl);
        }

        // ===================== IReusableAuth（批次连接复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            tp = new TextProto();
            tp.Connect(ip, port, timeoutSec, useSsl);
            string greeting = tp.ReadLine();
            if (!greeting.StartsWith("+OK", StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("POP3 服务拒绝连接: " + greeting);
            }
            banner = greeting;
            authedOnce = false;
        }

        public string Banner
        {
            get { return banner; }
        }

        public AuthResult TryAuth(string user, string password)
        {
            if (authedOnce)
            {
                return AuthResult.Closed;
            }
            try
            {
                if (Pop3Core.Auth(tp, user, password))
                {
                    authedOnce = true;
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
            try { tp?.SendLine("QUIT"); } catch { }
            try { tp?.Dispose(); } catch { }
            tp = null;
        }
    }

    internal static class Pop3Core
    {
        public static Server Run(string ip, int port, string username, string password, int timeOut, bool useSsl)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }
            using (TextProto tp = new TextProto())
            {
                tp.Connect(ip, port, timeOut, useSsl);
                string greeting = tp.ReadLine();
                if (!greeting.StartsWith("+OK", StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception("POP3 服务拒绝连接: " + greeting);
                }
                server.banner = greeting;

                server.isSuccess = Auth(tp, username, password);
                try { tp.SendLine("QUIT"); } catch { }
            }
            return server;
        }

        internal static bool Auth(TextProto tp, string username, string password)
        {
            tp.SendLine("USER " + username);
            string reply = tp.ReadLine();
            if (reply.StartsWith("+OK", StringComparison.OrdinalIgnoreCase))
            {
                tp.SendLine("PASS " + password);
                reply = tp.ReadLine();
            }

            if (reply.StartsWith("+OK", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            // coremail 等服务端密码过弱提示 —— 密码其实是对的
            return reply.IndexOf("weak", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
