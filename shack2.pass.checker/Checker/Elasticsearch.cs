using System;
using System.IO;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Elasticsearch 弱口令检测：GET / 的 X-Pack HTTP Basic 认证。
    /// 401 为口令错误；无认证集群（GET / 免认证 200）按开放访问标注。
    /// 实现 IReusableAuth：HTTP keep-alive 同连接连续尝试。
    /// </summary>
    class Elasticsearch : CheckerBase, IReusableAuth
    {
        private HttpWire http;
        private string banner = "Elasticsearch";
        private bool openAccess;

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            string pass = "空".Equals(password) ? "" : password;
            HttpWire h = new HttpWire();
            try
            {
                h.Connect(ip, port, timeOut);

                // 先无认证探测：免认证 200 说明集群未开启安全（开放访问）
                h.Get("/", null, null);
                if (h.Status == 200)
                {
                    server.isSuccess = true;
                    server.banner = ParseVersion(h.Body) + " 无认证(开放访问)";
                    return server;
                }
                if (h.Status != 401)
                {
                    server.banner = "HTTP " + h.Status + "（可能不是 Elasticsearch）";
                    return server;
                }
                if (!h.IsAlive)
                {
                    h.Dispose();
                    h = new HttpWire();
                    h.Connect(ip, port, timeOut);
                }
                h.Get("/", username, pass);
                if (h.Status == 200)
                {
                    server.isSuccess = true;
                    server.banner = ParseVersion(h.Body);
                }
                // 401/403：口令错误，正常失败
            }
            finally
            {
                h.Dispose();
            }
            return server;
        }

        // ===================== IReusableAuth（keep-alive 批次复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            http = new HttpWire();
            http.Connect(ip, port, timeoutSec);
            http.Get("/", null, null);
            openAccess = http.Status == 200;
            banner = openAccess ? ParseVersion(http.Body) + " 无认证(开放访问)" : "Elasticsearch";
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
                http.Get("/", user, password);
                if (http.Status == 200)
                {
                    if (banner == "Elasticsearch")
                    {
                        banner = ParseVersion(http.Body);
                    }
                    return AuthResult.Success;
                }
                if (http.Status == 401 || http.Status == 403)
                {
                    return AuthResult.Failed;
                }
                return AuthResult.Closed;
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

        /// <summary>从 GET / 的 JSON 应答提取版本号（"number":"8.x.x"）。</summary>
        private static string ParseVersion(string body)
        {
            const string key = "\"number\"";
            int i = body.IndexOf(key, StringComparison.Ordinal);
            if (i >= 0)
            {
                int colon = body.IndexOf(':', i + key.Length);
                int q1 = body.IndexOf('"', colon + 1);
                int q2 = body.IndexOf('"', q1 + 1);
                if (colon > 0 && q1 > colon && q2 > q1)
                {
                    return "Elasticsearch " + body.Substring(q1 + 1, q2 - q1 - 1);
                }
            }
            return "Elasticsearch";
        }
    }
}
