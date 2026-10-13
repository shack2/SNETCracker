using System;

namespace SNETCracker.Checker
{
    /// <summary>
    /// 达梦 DM8 弱口令检测：自实现最小客户端（DmWire），
    /// AUTH_SECURITY 握手 + 512 位 DH 密钥交换 + DES-CFB 口令加密登录，替代达梦官方驱动。
    /// </summary>
    class DM : CheckerBase
    {
        public DM()
        {

        }

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            using (DmWire conn = new DmWire())
            {
                conn.Connect(ip, port, timeOut);
                // 口令错误返回 false；网络/协议异常直接抛出，由上层计为检测失败
                if (conn.Login(username, "空".Equals(password) ? "" : password, out string error))
                {
                    server.isSuccess = true;
                    server.banner = conn.Banner();
                }
            }
            return server;
        }
    }
}
