using System;
using System.IO;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// WebLogic 弱口令检测：控制台表单登录（POST /console/j_security_check）。
    /// 判定：302 且下发 ADMINCONSOLESESSION Cookie 为成功；返回登录页为口令错误。
    /// 实现 IReusableAuth：HTTP keep-alive 同连接连续尝试。
    /// </summary>
    class WebLogic : CheckerBase, IReusableAuth
    {
        private HttpWire http;
        private string banner = "WebLogic";

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            string pass = "空".Equals(password) ? "" : password;
            using (HttpWire h = new HttpWire())
            {
                h.Connect(ip, port, timeOut);
                PostLogin(h, username, pass);

                string cookie = h.Header("Set-Cookie");
                if ((h.Status == 302 || h.Status == 303)
                    && cookie.IndexOf("ADMINCONSOLESESSION", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    server.isSuccess = true;
                    server.banner = h.Header("Server").Length > 0 ? h.Header("Server") : "WebLogic";
                }
                // 其余（回登录页 200/302）：口令错误，正常失败
            }
            return server;
        }

        private static void PostLogin(HttpWire h, string username, string password)
        {
            string form = "j_username=" + Uri.EscapeDataString(username)
                + "&j_password=" + Uri.EscapeDataString(password)
                + "&j_character_encoding=UTF-8";
            h.PostForm("/console/j_security_check", form);
        }

        // ===================== IReusableAuth（keep-alive 批次复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            http = new HttpWire();
            http.Connect(ip, port, timeoutSec);
            // 探测一次登录页拿 Server 头作 banner（不认证）
            try
            {
                http.Get("/console/login/LoginForm.jsp", null, null);
                if (http.Header("Server").Length > 0)
                {
                    banner = http.Header("Server");
                }
            }
            catch { banner = "WebLogic"; }
        }

        public string Banner
        {
            get { return banner; }
        }

        public AuthResult TryAuth(string user, string password)
        {
            if ("空".Equals(password))
            {
                password = "";
            }
            try
            {
                PostLogin(http, user, password);
                string cookie = http.Header("Set-Cookie");
                if ((http.Status == 302 || http.Status == 303)
                    && cookie.IndexOf("ADMINCONSOLESESSION", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (banner == "WebLogic" && http.Header("Server").Length > 0)
                    {
                        banner = http.Header("Server");
                    }
                    return AuthResult.Success;
                }
                // 回登录页：口令错误（连接保持可继续）
                return AuthResult.Failed;
            }
            catch (EndOfStreamException) { return AuthResult.Closed; }
            catch (IOException) { return AuthResult.Closed; }
            catch (SocketException) { return AuthResult.Closed; }
        }

        public void Dispose()
        {
            try { http?.Dispose(); } catch { }
            http = null;
        }
    }
}
