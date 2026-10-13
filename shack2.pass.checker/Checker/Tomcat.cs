using System;
using System.IO;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Tomcat 弱口令检测：Manager 后台（/manager/html）HTTP Basic 认证。
    /// 401 为口令错误；未认证即可访问（配置错误）按开放访问标注。
    /// 实现 IReusableAuth：HTTP keep-alive 同连接连续尝试，省每密码一次 TCP 握手。
    /// </summary>
    class Tomcat : CheckerBase, IReusableAuth
    {
        private HttpWire http;
        private string banner = "Tomcat";
        private bool openAccess;

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            string pass = "空".Equals(password) ? "" : password;
            using (HttpWire h = new HttpWire())
            {
                h.Connect(ip, port, timeOut);
                h.Get("/manager/html", username, pass);
                if (h.Status == 200)
                {
                    server.isSuccess = true;
                    server.banner = h.Header("Server").Length > 0 ? h.Header("Server") : "Tomcat";
                }
                else if (h.Status == 401 || h.Status == 403)
                {
                    // 口令错误，正常失败
                }
                else
                {
                    server.banner = "HTTP " + h.Status + "（可能不是 Tomcat Manager 路径）";
                }
            }
            return server;
        }

        // ===================== IReusableAuth（keep-alive 批次复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            http = new HttpWire();
            http.Connect(ip, port, timeoutSec);
            // 探测一次：捕获 Server 头 + 识别未认证开放（配置错误）
            http.Get("/manager/html", null, null);
            banner = http.Header("Server").Length > 0 ? http.Header("Server") : "Tomcat";
            openAccess = http.Status == 200;
            if (openAccess)
            {
                banner += "（无认证，开放访问）";
            }
        }

        public string Banner
        {
            get { return banner; }
        }

        public AuthResult TryAuth(string user, string password)
        {
            if (openAccess)
            {
                return AuthResult.Success;
            }
            if ("空".Equals(password))
            {
                password = "";
            }
            try
            {
                http.Get("/manager/html", user, password);
                if (http.Status == 200)
                {
                    return AuthResult.Success;
                }
                if (http.Status == 401 || http.Status == 403)
                {
                    return AuthResult.Failed;
                }
                return AuthResult.Closed; // 非常规应答：连接状态不可信，重连
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
