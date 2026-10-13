using System;
using System.IO;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// IMAP 弱口令检测：自实现 LOGIN 命令（tagged OK/NO/BAD 判定），替代 MailKit。
    /// 实现 IReusableAuth：LOGIN 失败（NO/BAD）连接保持，同一连接可连续尝试。
    /// </summary>
    class IMAP : CheckerBase, IReusableAuth
    {
        private readonly bool useSsl;
        private TextProto tp;
        private string banner = "IMAP";
        private bool authedOnce; // 成功后进入 authenticated 态：下次 TryAuth 返回 Closed 强制重连

        public IMAP()
        {
            useSsl = false;
        }

        protected IMAP(bool useSsl)
        {
            this.useSsl = useSsl;
        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            return ImapCore.Run(ip, port, username, password, timeOut, useSsl);
        }

        // ===================== IReusableAuth（批次连接复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            tp = new TextProto();
            tp.Connect(ip, port, timeoutSec, useSsl);
            string greeting = tp.ReadLine();
            if (!greeting.StartsWith("* OK", StringComparison.OrdinalIgnoreCase)
                && !greeting.StartsWith("* PREAUTH", StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("IMAP 服务拒绝连接: " + greeting);
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
                if (ImapCore.Auth(tp, user, password))
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
            try { tp?.SendLine("a9 LOGOUT"); } catch { }
            try { tp?.Dispose(); } catch { }
            tp = null;
        }
    }

    internal static class ImapCore
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
                if (!greeting.StartsWith("* OK", StringComparison.OrdinalIgnoreCase)
                    && !greeting.StartsWith("* PREAUTH", StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception("IMAP 服务拒绝连接: " + greeting);
                }
                server.banner = greeting;

                server.isSuccess = Auth(tp, username, password);
                try { tp.SendLine("a2 LOGOUT"); } catch { }
            }
            return server;
        }

        internal static bool Auth(TextProto tp, string username, string password)
        {
            const string tag = "a1";
            tp.SendLine(tag + " LOGIN \"" + Escape(username) + "\" \"" + Escape(password) + "\"");
            // 读到带 tag 的完成行为止（跳过 untagged 行）
            string line;
            do
            {
                line = tp.ReadLine();
            } while (!line.StartsWith(tag + " ", StringComparison.Ordinal));

            // OK 成功；NO/BAD 均为认证失败
            return line.StartsWith(tag + " OK", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>IMAP quoted-string 转义：反斜杠与双引号。</summary>
        private static string Escape(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
