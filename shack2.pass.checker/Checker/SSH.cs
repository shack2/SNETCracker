using System;

namespace SNETCracker.Checker
{
    /// <summary>
    /// SSH 弱口令检测：自实现最小客户端（SshWire），
    /// 横幅 + curve25519-sha256/ecdh-sha2-nistp256/dh-group14-sha256 密钥交换
    /// + password/keyboard-interactive 认证，替代 SSH.NET + BouncyCastle。
    /// 实现 IReusableAuth：同一连接连续认证（服务端 password 不可用时自动降级 keyboard-interactive）。
    /// </summary>
    class SSH : CheckerBase, IReusableAuth
    {
        private SshWire wire;
        private bool preferKi; // 服务端不支持 password 时降级，本连接后续直接用 keyboard-interactive

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            using (SshWire client = new SshWire())
            {
                client.Connect(ip, port, timeOut);
                // 口令错误返回 false；网络/协议异常直接抛出，由上层计为检测失败
                if (client.Login(username, "空".Equals(password) ? "" : password))
                {
                    server.isSuccess = true;
                    server.banner = client.Banner();
                }
            }
            return server;
        }

        // ===================== IReusableAuth（批次连接复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            wire = new SshWire();
            wire.Connect(ip, port, timeoutSec);
            wire.Handshake();
            preferKi = false;
        }

        public string Banner
        {
            get { return wire != null ? wire.Banner() : "SSH"; }
        }

        public AuthResult TryAuth(string user, string password)
        {
            if (preferKi)
            {
                return wire.TryKeyboardInteractive(user, password);
            }
            AuthResult r = wire.TryPassword(user, password);
            if (r == AuthResult.Failed && !wire.MethodAllowed("password") && wire.MethodAllowed("keyboard-interactive"))
            {
                // 服务端不支持 password（FreeBSD/PAM 设备常见）：降级并记住，本连接后续直接 ki
                preferKi = true;
                r = wire.TryKeyboardInteractive(user, password);
            }
            return r;
        }

        public void Dispose()
        {
            try { wire?.Dispose(); } catch { }
            wire = null;
        }
    }
}
