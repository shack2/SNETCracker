using SNETCracker.Except;
using System;

namespace SNETCracker.Checker
{
    /// <summary>
    /// PostgreSQL 弱口令检测：自实现最小客户端（PostgresWire），
    /// v3 启动包 + cleartext/MD5/SCRAM-SHA-256 认证，替代 Npgsql。
    /// </summary>
    class PostgreSQL : CheckerBase
    {
        public PostgreSQL()
        {

        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            using (PostgresWire conn = new PostgresWire())
            {
                conn.Connect(ip, port, timeOut);
                try
                {
                    // 口令错误返回 false；网络/协议异常直接抛出，由上层计为检测失败
                    if (conn.Login(username, "空".Equals(password) ? "" : password, "postgres", out string error))
                    {
                        server.isSuccess = true;
                        server.banner = conn.Banner();
                    }
                }
                catch (PostgresWire.PgAuthException e) when (e.SqlState == "28000")
                {
                    // 与旧 Npgsql 行为一致：28000（如 pg_hba 拒绝）跳过该 IP
                    throw new IPBreakException(ip + port);
                }
            }
            return server;
        }
    }
}
