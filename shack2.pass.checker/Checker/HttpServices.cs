using System;
using System.IO;
using System.Net.Sockets;
using Tools;

namespace SNETCracker.Checker
{
    /// <summary>
    /// HTTP Basic 认证检测基类（HTTPS/WinRM/ActiveMQ 共用）：
    /// keep-alive 连接复用 + 401/403 判失败 / 2xx 判成功 / 其他判连接不可信。
    /// 子类只声明路径、TLS、请求方法与 banner 提取。
    /// </summary>
    internal abstract class HttpAuthBase : CheckerBase, IReusableAuth
    {
        protected abstract bool UseSsl { get; }
        protected abstract string RequestPath { get; }
        protected virtual string Method => "GET";
        protected virtual string PostBody => null;
        protected virtual string PostContentType => null;
        protected virtual string DefaultBanner => "HTTP Basic";

        private HttpWire http;
        private string banner;
        private bool openAccess;

        /// <summary>状态码 → 认证结果；默认 401/403 失败、2xx 成功、其他连接不可信。</summary>
        protected virtual AuthResult MapStatus(int status)
        {
            if (status == 401 || status == 403)
            {
                return AuthResult.Failed;
            }
            if (status >= 200 && status < 300)
            {
                return AuthResult.Success;
            }
            return AuthResult.Closed;
        }

        /// <summary>从响应提取 banner（默认 Server 头）。</summary>
        protected virtual string ExtractBanner(HttpWire h)
        {
            string srv = h.Header("Server");
            return srv.Length > 0 ? srv : DefaultBanner;
        }

        private void SendRequest(string user, string pass)
        {
            if (Method == "POST")
            {
                http.Post(RequestPath, user, pass, PostBody ?? "", PostContentType ?? "text/plain");
            }
            else
            {
                http.Get(RequestPath, user, pass);
            }
        }

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            string pass = "空".Equals(password) ? "" : password;
            using (HttpWire h = new HttpWire())
            {
                h.Connect(ip, port, timeOut, UseSsl);
                if (Method == "POST")
                {
                    h.Post(RequestPath, username, pass, PostBody ?? "", PostContentType ?? "text/plain");
                }
                else
                {
                    h.Get(RequestPath, username, pass);
                }
                AuthResult r = MapStatus(h.Status);
                if (r == AuthResult.Success)
                {
                    server.isSuccess = true;
                    server.banner = ExtractBanner(h);
                }
                else if (r == AuthResult.Closed)
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
            http.Connect(ip, port, timeoutSec, UseSsl);
            // 探测一次：识别免认证开放（无认证 2xx）
            SendRequest(null, null);
            openAccess = http.Status >= 200 && http.Status < 300;
            banner = ExtractBanner(http);
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
                SendRequest(user, password);
                return MapStatus(http.Status);
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

    /// <summary>HTTPS Basic 认证检测：与 HTTP 相同，传输层套 TLS。路径复用 config/http.txt。</summary>
    internal sealed class HttpsBasic : HttpAuthBase
    {
        private readonly string cfgPath = FileTool.readFileToString(AppDomain.CurrentDomain.BaseDirectory + "/config/http.txt");

        protected override bool UseSsl => true;

        protected override string RequestPath
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

        protected override string DefaultBanner => "HTTPS Basic";
    }

    /// <summary>
    /// WinRM（WS-Man）检测：POST /wsman + Basic 认证。
    /// 认证在 HTTP 层先于 SOAP 解析：401/403 口令错误；其余状态（含 500 SOAP Fault）
    /// 说明请求已通过认证进入 WS-Man 处理，判成功。
    /// </summary>
    internal sealed class WinRm : HttpAuthBase
    {
        protected override bool UseSsl => false;
        protected override string RequestPath => "/wsman";
        protected override string Method => "POST";
        protected override string PostContentType => "application/soap+xml;charset=UTF-8";
        protected override string PostBody =>
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">" +
            "<s:Header><w:OperationTimeout>PT30S</w:OperationTimeout></s:Header><s:Body/></s:Envelope>";
        protected override string DefaultBanner => "WinRM (WS-Man)";

        protected override AuthResult MapStatus(int status)
        {
            if (status == 401 || status == 403)
            {
                return AuthResult.Failed;
            }
            // 通过认证后 WS-Man 对空 Body 也回 SOAP Fault(500)，同样证明口令正确
            return AuthResult.Success;
        }
    }

    /// <summary>ActiveMQ Web 控制台检测：GET /admin/（8161，Basic 认证，302/200 通过）。</summary>
    internal sealed class ActiveMq : HttpAuthBase
    {
        protected override bool UseSsl => false;
        protected override string RequestPath => "/admin/";
        protected override string DefaultBanner => "ActiveMQ Console";

        protected override AuthResult MapStatus(int status)
        {
            if (status == 401 || status == 403)
            {
                return AuthResult.Failed;
            }
            if (status >= 200 && status < 400)
            {
                return AuthResult.Success; // 控制台登录后 302 跳转
            }
            return AuthResult.Closed;
        }
    }
}
