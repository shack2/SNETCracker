using SNETCracker.Except;
using System;

namespace SNETCracker.Checker
{
    /// <summary>
    /// KingbaseES（人大金仓）弱口令检测：Kingbase 兼容 PostgreSQL v3 前端/后端协议，
    /// 直接复用 PostgresWire（cleartext/MD5/SCRAM-SHA-256 认证）。
    /// 与 PG 的差异：Kingbase 默认端口 54321，且认证先于库校验 ——
    /// 返回 3D000（库不存在）说明口令已验证通过，视为成功。
    /// </summary>
    class Kingbase : CheckerBase
    {
        public Kingbase()
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
                    if (conn.Login(username, "空".Equals(password) ? "" : password, "test", out string error))
                    {
                        server.isSuccess = true;
                        server.banner = Banner(conn);
                    }
                }
                catch (PostgresWire.PgAuthException e) when (e.SqlState == "3D000")
                {
                    // 库不存在：Kingbase 先认证后校验库名，到这一步说明口令正确
                    server.isSuccess = true;
                    server.banner = Banner(conn);
                }
                catch (PostgresWire.PgAuthException e) when (e.SqlState == "28000")
                {
                    // 与 PG 行为一致：28000（如 hba 拒绝）跳过该 IP
                    throw new IPBreakException(ip + port);
                }
            }
            return server;
        }

        private static string Banner(PostgresWire conn)
        {
            string v = conn.ServerVersion;
            if (v.Length == 0)
            {
                return "KingbaseES";
            }
            return v.IndexOf("Kingbase", StringComparison.OrdinalIgnoreCase) >= 0 ? v : "KingbaseES " + v;
        }
    }
}
