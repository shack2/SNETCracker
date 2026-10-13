using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// SMTP 弱口令检测：自实现 EHLO + AUTH LOGIN / AUTH PLAIN，
    /// 替代 MailKit/MimeKit（约 2.3 MB IL）。保留 coremail「weak 提示也算成功」兼容逻辑。
    /// 实现 IReusableAuth：AUTH 失败（535）连接保持，同一连接可连续尝试。
    /// </summary>
    class SMTP : CheckerBase, IReusableAuth
    {
        private readonly bool useSsl;
        private TextProto tp;
        private string banner = "SMTP";
        private string ehlo = "";
        private bool authedOnce; // 235 后服务端进入已认证态：下次 TryAuth 返回 Closed 强制重连

        public SMTP()
        {
            useSsl = false;
        }

        protected SMTP(bool useSsl)
        {
            this.useSsl = useSsl;
        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            return SmtpCore.Run(ip, port, username, password, timeOut, useSsl);
        }

        // ===================== IReusableAuth（批次连接复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            tp = new TextProto();
            tp.Connect(ip, port, timeoutSec, useSsl);
            int rc = tp.ReadFtpReply(out string greeting);   // 220 问候（SMTP 也是 code[-]text 多行格式）
            if (rc / 100 != 2)
            {
                throw new Exception("SMTP 服务拒绝连接: " + greeting);
            }
            banner = greeting;

            // EHLO（失败则退 HELO），顺带取 AUTH 能力列表，一次握手缓存复用
            tp.SendLine("EHLO password-checker");
            rc = tp.ReadFtpReply(out ehlo);
            if (rc != 250)
            {
                tp.SendLine("HELO password-checker");
                tp.ReadFtpReply(out _);
                ehlo = "";
            }
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
                if (SmtpCore.Auth(tp, user, password, ehlo))
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

    internal static class SmtpCore
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
                int rc = tp.ReadFtpReply(out string greeting);   // 220 问候（SMTP 也是 code[-]text 多行格式）
                if (rc / 100 != 2)
                {
                    throw new Exception("SMTP 服务拒绝连接: " + greeting);
                }
                server.banner = greeting;

                // EHLO（失败则退 HELO），顺带取 AUTH 能力列表
                tp.SendLine("EHLO password-checker");
                rc = tp.ReadFtpReply(out string ehlo);
                if (rc != 250)
                {
                    tp.SendLine("HELO password-checker");
                    tp.ReadFtpReply(out _);
                    ehlo = "";
                }

                server.isSuccess = Auth(tp, username, password, ehlo);
                try { tp.SendLine("QUIT"); } catch { }
            }
            return server;
        }

        internal static bool Auth(TextProto tp, string user, string password, string ehlo)
        {
            bool loginOk = ehlo.IndexOf("AUTH", StringComparison.OrdinalIgnoreCase) < 0
                || ehlo.IndexOf("LOGIN", StringComparison.OrdinalIgnoreCase) >= 0;
            if (loginOk)
            {
                int? rc = AuthLogin(tp, user, password, out string reply);
                if (rc.HasValue)
                {
                    return rc.Value == 235 || IsWeakHint(rc.Value, reply);
                }
            }
            // AUTH PLAIN 兜底
            return AuthPlain(tp, user, password);
        }

        /// <summary>返回状态码；协议不支持 AUTH LOGIN 返回 null。</summary>
        private static int? AuthLogin(TextProto tp, string user, string password, out string reply)
        {
            tp.SendLine("AUTH LOGIN");
            int rc = tp.ReadFtpReply(out reply);
            if (rc / 100 == 5)
            {
                return null;    // 服务端不支持 LOGIN，换 PLAIN
            }
            tp.SendLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(user)));
            rc = tp.ReadFtpReply(out reply);
            if (rc != 334)
            {
                return rc;      // 用户名阶段即被拒
            }
            tp.SendLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(password)));
            rc = tp.ReadFtpReply(out reply);
            return rc;
        }

        private static bool AuthPlain(TextProto tp, string user, string password)
        {
            string token = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0" + user + "\0" + password));
            tp.SendLine("AUTH PLAIN " + token);
            int rc = tp.ReadFtpReply(out string reply);
            return rc == 235 || IsWeakHint(rc, reply);
        }

        /// <summary>coremail 等服务端密码过弱时会返回含 weak 的 5xx —— 密码其实是对的。</summary>
        private static bool IsWeakHint(int rc, string reply)
        {
            return rc / 100 == 5
                && reply != null
                && reply.IndexOf("weak", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
