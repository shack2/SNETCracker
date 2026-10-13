using System;

namespace SNETCracker.Checker
{
    /// <summary>
    /// SQL Server 弱口令检测：自实现最小客户端（TdsWire），
    /// Pre-Login + Login7 SQL 身份验证，替代 Microsoft.Data.SqlClient（含原生 SNI.dll）。
    /// </summary>
    class SQLServer : CheckerBase
    {
        public SQLServer()
        {

        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            using (TdsWire conn = new TdsWire())
            {
                conn.Connect(ip, port, timeOut);
                // 口令错误(18456)返回 false；网络/协议异常直接抛出，由上层计为检测失败
                if (conn.Login(username, "空".Equals(password) ? "" : password, out string error))
                {
                    server.isSuccess = true;
                    server.banner = conn.Banner();
                }
                else
                {
                    server.banner = error; // 失败原因（18456: ...），便于诊断
                }
            }
            return server;
        }
    }
}
