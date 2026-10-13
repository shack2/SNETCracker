using System;
using System.IO;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// FTP 弱口令检测：自实现 FTP 控制通道（USER/PASS/SYST），
    /// 替代 FluentFTP（约 0.5 MB IL）。支持多行应答解析。
    /// 实现 IReusableAuth：530 失败后连接保持，同一连接可连续 USER/PASS。
    /// </summary>
    class FTP : CheckerBase, IReusableAuth
    {
        private readonly bool useSsl;
        private TextProto tp;
        private string banner = "FTP";
        private bool authedOnce; // 已成功过：下次 TryAuth 返回 Closed 强制重连

        public FTP()
        {
            useSsl = false;
        }

        protected FTP(bool useSsl)
        {
            this.useSsl = useSsl;
            banner = useSsl ? "FTPS" : "FTP";
        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }
            using (TextProto tp = new TextProto())
            {
                tp.Connect(ip, port, timeOut, useSsl);
                int rc = tp.ReadFtpReply(out string greeting);
                if (rc / 100 != 2)
                {
                    throw new Exception("FTP 服务拒绝连接: " + greeting);
                }

                bool ok = LoginOnce(tp, username, password);
                if (ok)
                {
                    server.isSuccess = true;
                    server.banner = ReadSyst(tp, greeting);
                    try { tp.SendLine("QUIT"); } catch { }
                }
            }
            return server;
        }

        // ===================== IReusableAuth（批次连接复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            tp = new TextProto();
            tp.Connect(ip, port, timeoutSec, useSsl);
            int rc = tp.ReadFtpReply(out string greeting);
            if (rc / 100 != 2)
            {
                throw new Exception("FTP 服务拒绝连接: " + greeting);
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
                return AuthResult.Closed; // 已成功：强制新连接（已登录态下再认证语义不一）
            }
            try
            {
                if (LoginOnce(tp, user, password))
                {
                    authedOnce = true;
                    banner = ReadSyst(tp, banner);
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

        /// <summary>执行一次 USER/PASS 登录，返回是否登录成功。</summary>
        private static bool LoginOnce(TextProto tp, string username, string password)
        {
            int rc = SendAndRead(tp, "USER " + username, out _);
            if (rc == 230)
            {
                return true;  // 无需密码直接登录成功（匿名类）
            }
            if (rc == 331 || rc == 332)
            {
                return SendAndRead(tp, "PASS " + password, out _) / 100 == 2;
            }
            return false;     // USER 即 5xx：失败
        }

        private static string ReadSyst(TextProto tp, string fallback)
        {
            try
            {
                if (SendAndRead(tp, "SYST", out string syst) / 100 == 2)
                {
                    return syst;
                }
            }
            catch { }
            return fallback;
        }

        private static int SendAndRead(TextProto tp, string cmd, out string text)
        {
            tp.SendLine(cmd);
            return tp.ReadFtpReply(out text);
        }
    }
}
