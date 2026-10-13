using System;
using System.IO;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// MongoDB 弱口令检测：自实现最小客户端（MongoWire），
    /// 支持 SCRAM-SHA-1 / SCRAM-SHA-256 与未授权访问探测，兼容 MongoDB 2.6+。
    /// 实现 IReusableAuth：SCRAM 失败连接保持，同一连接可连续发起新认证对话。
    /// </summary>
    class MongoDB : CheckerBase, IReusableAuth
    {
        private MongoWire conn;
        private string banner = "MongoDB";
        private bool authedOnce; // 已成功过：下次 TryAuth 返回 Closed 强制重连（避免已认证态误报）

        public MongoDB()
        {

        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            using (MongoWire conn = new MongoWire())
            {
                conn.Connect(ip, port, timeOut);
                conn.Hello();

                if ("空".Equals(password))
                {
                    // 未授权访问探测：不认证直接执行 buildInfo，成功即服务端未启用访问控制
                    BsonDoc probe = conn.Command("admin", BsonWriter.Doc().Int32("buildInfo", 1));
                    if (probe.Ok)
                    {
                        server.isSuccess = true;
                        server.banner = "MongoDB " + probe.Str("version") + "（未授权访问）";
                    }
                    return server;
                }

                if (conn.Authenticate(username, password, out string error))
                {
                    server.isSuccess = true;
                    server.banner = ReadVersionBanner(conn);
                }
            }
            return server;
        }

        // ===================== IReusableAuth（批次连接复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            conn = new MongoWire();
            conn.Connect(ip, port, timeoutSec);
            conn.Hello();
            banner = "MongoDB (maxWireVersion=" + conn.MaxWireVersion + ")";
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
                if (password.Length == 0)
                {
                    // 未授权访问探测：不认证直接执行 buildInfo
                    BsonDoc probe = conn.Command("admin", BsonWriter.Doc().Int32("buildInfo", 1));
                    if (probe.Ok)
                    {
                        authedOnce = true;
                        banner = "MongoDB " + probe.Str("version") + "（未授权访问）";
                        return AuthResult.Success;
                    }
                    return AuthResult.Failed;
                }
                if (conn.Authenticate(user, password, out _))
                {
                    authedOnce = true;
                    banner = ReadVersionBanner(conn);
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
            try { conn?.Dispose(); } catch { }
            conn = null;
        }

        private static string ReadVersionBanner(MongoWire conn)
        {
            BsonDoc bi = conn.Command("admin", BsonWriter.Doc().Int32("buildInfo", 1));
            return bi.Ok
                ? "MongoDB " + bi.Str("version")
                : "MongoDB (maxWireVersion=" + conn.MaxWireVersion + ")";
        }
    }
}
