using SNETCracker.Except;
using System;

namespace SNETCracker.Checker
{
    /// <summary>
    /// ClickHouse 弱口令检测：自实现最小客户端（ClickHouseWire），
    /// 原生 TCP 协议 Hello 握手认证（默认端口 9000，HTTP 端口 8123 不支持）。
    /// </summary>
    class ClickHouse : CheckerBase
    {
        public ClickHouse()
        {

        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            using (ClickHouseWire conn = new ClickHouseWire())
            {
                conn.Connect(ip, port, timeOut);
                try
                {
                    // 口令错误返回 false；网络/协议异常直接抛出，由上层计为检测失败
                    if (conn.Login(username, "空".Equals(password) ? "" : password, "default", out string error))
                    {
                        server.isSuccess = true;
                        server.banner = conn.Banner();
                    }
                }
                catch (ClickHouseWire.ChAuthException e) when (e.Code == 81 || e.Code == 372 || e.Code == 497)
                {
                    // 81 UNKNOWN_DATABASE（到这里说明口令已对）；
                    // 372 SESSION_IS_LOCKED / 497 ACCESS_DENIED 的 IP 封禁类错误视为本机被拒，跳过该 IP
                    if (e.Code == 81)
                    {
                        server.isSuccess = true;
                        server.banner = conn.Banner();
                    }
                    else
                    {
                        throw new IPBreakException(ip + port);
                    }
                }
            }
            return server;
        }
    }
}
