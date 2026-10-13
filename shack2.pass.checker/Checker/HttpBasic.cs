using System;
using System.IO;
using System.Net.Sockets;
using Tools;

namespace SNETCracker.Checker
{
    /// <summary>
    /// HTTP 通用 Basic 认证检测：对可配置路径发起带 Basic 认证的 GET。
    /// 路径取自 config/http.txt（缺省 /）。401/403 为口令错误；
    /// 免认证 200 按开放访问标注；其余 2xx 判认证成功。
    /// 实现 IReusableAuth：HTTP keep-alive 同连接连续尝试。
    /// </summary>
    class HttpBasic : CheckerBase, IReusableAuth
    {
        private readonly string cfgPath = FileTool.readFileToString(AppDomain.CurrentDomain.BaseDirectory + "/config/http.txt");
        private HttpWire http;
        private string banner = "HTTP Basic";
        private bool openAccess;

        public HttpBasic()
        {

        }

        private string Path
        {
            get
            {
                string path = cfgPath == null ? "" : cfgPath.Trim();
                if (path.Length == 0)
                {
                    path = "/";
                }
                if (!path.StartsWith("/"))
                {
                    path = "/" + path;
                }
                return path;
            }
        }

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            string pass = "空".Equals(password) ? "" : password;

            using (HttpWire h = new HttpWire())
            {
                h.Connect(ip, port, timeOut);
                h.Get(Path, username, pass);
                if (h.Status == 401 || h.Status == 403)
                {
                    // 口令错误，正常失败
                }
                else if (h.Status >= 200 && h.Status < 300)
                {
                    server.isSuccess = true;
                    string srv = h.Header("Server");
                    server.banner = srv.Length > 0 ? srv : "HTTP Basic";
                }
                else
                {
                    server.banner = "HTTP " + h.Status;
                }
            }
            return server;
        }

        // ===================== IReusableAuth（keep-alive 批次复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            http = new HttpWire();
            http.Connect(ip, port, timeoutSec);
            // 探测一次：识别免认证开放（无认证 200）
            http.Get(Path, null, null);
            openAccess = http.Status >= 200 && http.Status < 300;
            banner = http.Header("Server").Length > 0 ? http.Header("Server") : "HTTP Basic";
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
                http.Get(Path, user, password);
                if (http.Status == 401 || http.Status == 403)
                {
                    return AuthResult.Failed;
                }
                if (http.Status >= 200 && http.Status < 300)
                {
                    return AuthResult.Success;
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
