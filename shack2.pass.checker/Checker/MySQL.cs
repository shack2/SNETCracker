using SNETCracker.Except;
using System;

namespace SNETCracker.Checker
{
    /// <summary>
    /// MySQL 弱口令检测：自实现最小客户端（MySqlWire），
    /// v10 握手 + mysql_native_password / caching_sha2_password 认证，替代 MySqlConnector。
    /// </summary>
    class MySQL : CheckerBase
    {
        public MySQL()
        {

        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            using (MySqlWire conn = new MySqlWire())
            {
                conn.Connect(ip, port, timeOut);
                try
                {
                    // 口令错误(1045)返回 false；网络/协议异常直接抛出，由上层计为检测失败
                    if (conn.Login(username, "空".Equals(password) ? "" : password, out string error))
                    {
                        server.isSuccess = true;
                        server.banner = conn.Banner();
                    }
                }
                catch (MySqlWire.MySqlAuthException e) when (e.Code == 1129 || e.Code == 1130 || e.Code == 1226)
                {
                    // 与旧行为一致：主机被拉黑/不允许/超出连接数 → 跳过该 IP
                    throw new IPBreakException(ip + port);
                }
            }
            return server;
        }
    }
}
