using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// MySQL 最小客户端：仅实现弱口令检测所需的能力 ——
    /// v10 握手 + mysql_native_password（SHA1 两轮）与 caching_sha2_password（SHA256 两轮，含 RSA 全量认证）。
    /// 替代 MySqlConnector（约 0.9 MB IL）。协议参考 MySQL 官方 internals 文档。
    /// 零第三方依赖、AOT 安全。覆盖：MySQL 5.x / 8.x、MariaDB 10.x。
    /// 不支持：TLS（auth 直接走明文握手）、caching_sha2 的 TLS 全量认证变体（用 RSA 公钥变体代替）。
    /// </summary>
    internal sealed class MySqlWire : IDisposable
    {
        private const byte CmdOk = 0x00, CmdErr = 0xff, CmdAuthSwitch = 0xfe, CmdAuthMore = 0x01;

        private Socket sock;
        private int seq;

        /// <summary>服务端版本串（握手包）。</summary>
        public string ServerVersion = "";

        public void Connect(string ip, int port, int timeoutSec)
        {
            sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            IAsyncResult ar = sock.BeginConnect(ip, port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(timeoutSec)))
            {
                try { sock.Close(); } catch { }
                throw new TimeoutException("连接超时");
            }
            sock.EndConnect(ar);
            sock.ReceiveTimeout = timeoutSec * 1000;
            sock.SendTimeout = timeoutSec * 1000;
        }

        /// <summary>认证；口令错误返回 false（error 为服务端错误文本），网络/协议异常直接抛出。
        /// 主机被拒/拉黑（1129/1130 等）抛 MySqlAuthException 由上层转 IPBreakException。</summary>
        public bool Login(string user, string password, out string error)
        {
            error = null;

            // 1) 握手包
            seq = 0;
            byte[] hs = RecvPacket();
            if (hs.Length == 0 || hs[0] != 10)
            {
                if (hs.Length > 0 && hs[0] == CmdErr) ThrowErr(hs); // 老版本直接回 ERR
                throw new Exception("MySQL 握手包异常");
            }
            int pos = 1;
            int z = Array.IndexOf(hs, (byte)0, pos);
            ServerVersion = Encoding.ASCII.GetString(hs, pos, z - pos);
            pos = z + 1 + 4; // 跳过连接 ID
            byte[] seed1 = new byte[8];
            Buffer.BlockCopy(hs, pos, seed1, 0, 8);
            pos += 9; // +1 filler
            if (hs.Length < pos + 2 + 1 + 2 + 2 + 1 + 10)
            {
                throw new Exception("MySQL 握手包过短");
            }
            int capLow = hs[pos] | (hs[pos + 1] << 8);
            pos += 2 + 1 + 2; // 字符集 + 状态
            int capHigh = hs[pos] | (hs[pos + 1] << 8); pos += 2;
            int caps = capLow | (capHigh << 16);
            int authDataLen = hs[pos]; pos += 1 + 10;
            // seed 第二部分：max(13, authDataLen-8)，以 \0 结尾
            int seed2Len = Math.Max(13, authDataLen - 8);
            byte[] seed2 = new byte[seed2Len];
            int avail = Math.Min(seed2Len, hs.Length - pos);
            if (avail > 0) Buffer.BlockCopy(hs, pos, seed2, 0, avail);
            pos += seed2Len;
            string plugin = "mysql_native_password";
            if ((caps & 0x00080000) != 0 && pos < hs.Length) // CLIENT_PLUGIN_AUTH
            {
                int e = Array.IndexOf(hs, (byte)0, pos);
                if (e > pos) plugin = Encoding.ASCII.GetString(hs, pos, e - pos);
            }
            byte[] seed = Concat(seed1, TrimZero(seed2)); // 20 字节挑战

            // 2) 登录包（明文模式：不置 CLIENT_SSL）
            const int myCaps = 0x00000001 | 0x00000200 | 0x00002000 | 0x00008000 | 0x00080000 | 0x00020000;
            byte[] token = BuildToken(plugin, password, seed);
            var ms = new MemoryStream();
            W4LE(ms, myCaps); W4LE(ms, 16 * 1024 * 1024);
            ms.WriteByte(33); // utf8_general_ci
            ms.Write(new byte[23], 0, 23);
            WCStr(ms, user);
            ms.WriteByte((byte)token.Length);
            ms.Write(token, 0, token.Length);
            WCStr(ms, plugin);
            SendPacket(ms.ToArray());

            // 3) 响应：OK / ERR / AuthSwitch / AuthMoreData
            for (int round = 0; round < 4; round++)
            {
                byte[] resp = RecvPacket();
                if (resp.Length == 0) throw new Exception("MySQL 响应为空");
                if (resp[0] == CmdOk) return true;
                if (resp[0] == CmdErr)
                {
                    int code = resp.Length >= 3 ? resp[1] | (resp[2] << 8) : 0;
                    string msg = resp.Length > 9 && resp[3] == (byte)'#'
                        ? Encoding.UTF8.GetString(resp, 9, resp.Length - 9)
                        : Encoding.UTF8.GetString(resp, 3, resp.Length - 3);
                    if (code == 1045) // ER_ACCESS_DENIED：口令错误，正常失败
                    {
                        error = code + ": " + msg;
                        return false;
                    }
                    throw new MySqlAuthException(code, msg);
                }
                if (resp[0] == CmdAuthSwitch && resp.Length > 1) // AuthSwitchRequest：换认证插件
                {
                    int e = Array.IndexOf(resp, (byte)0, 1);
                    string newPlugin = Encoding.ASCII.GetString(resp, 1, e - 1);
                    byte[] newSeed = new byte[resp.Length - e - 1];
                    Buffer.BlockCopy(resp, e + 1, newSeed, 0, newSeed.Length);
                    newSeed = TrimZero(newSeed);
                    SendPacket(BuildToken(newPlugin, password, newSeed));
                    continue;
                }
                if (resp[0] == CmdAuthMore && resp.Length >= 2) // caching_sha2_password 后续
                {
                    if (resp[1] == 3) continue;              // fast auth 成功，下一个包是 OK
                    if (resp[1] == 4)                        // full auth：RSA 公钥加密
                    {
                        SendPacket(new byte[] { 2 });        // 请求服务端公钥
                        byte[] keyPkt = RecvPacket();
                        if (keyPkt.Length == 0 || keyPkt[0] != CmdAuthMore)
                        {
                            throw new Exception("获取服务端 RSA 公钥失败");
                        }
                        byte[] enc = RsaEncryptPassword(password, seed, Encoding.ASCII.GetString(keyPkt, 1, keyPkt.Length - 1));
                        SendPacket(enc);
                        continue;
                    }
                    throw new Exception("caching_sha2 未知子状态: " + resp[1]);
                }
                throw new Exception("MySQL 响应类型异常: 0x" + resp[0].ToString("x2"));
            }
            throw new Exception("MySQL 认证轮次过多");
        }

        /// <summary>取服务端标识用于 Banner 展示。</summary>
        public string Banner()
        {
            return ServerVersion.Length > 0 ? "MySQL " + ServerVersion : "MySQL";
        }

        public void Dispose()
        {
            try { sock?.Close(); } catch { }
        }

        // ===================== 认证算法 =====================

        private static byte[] BuildToken(string plugin, string password, byte[] seed)
        {
            if (password.Length == 0) return new byte[0];
            byte[] pwd = Encoding.UTF8.GetBytes(password);
            if (plugin == "caching_sha2_password")
            {
                // XOR(SHA256(p), SHA256(SHA256(SHA256(p)) + seed))
                byte[] p1 = SHA256.HashData(pwd);
                byte[] p2 = SHA256.HashData(p1);
                byte[] p3 = SHA256.HashData(Concat(p2, seed));
                return Xor(p1, p3);
            }
            // mysql_native_password（默认）：XOR(SHA1(p), SHA1(seed + SHA1(SHA1(p))))
            byte[] h1 = SHA1.HashData(pwd);
            byte[] h2 = SHA1.HashData(h1);
            byte[] h3 = SHA1.HashData(Concat(seed, h2));
            return Xor(h1, h3);
        }

        /// <summary>caching_sha2 full auth：password\0 与 seed 循环异或后用服务端 RSA 公钥 OAEP(SHA1) 加密。</summary>
        private static byte[] RsaEncryptPassword(string password, byte[] seed, string pem)
        {
            byte[] pwd = Encoding.UTF8.GetBytes(password + "\0");
            byte[] xored = new byte[pwd.Length];
            for (int i = 0; i < pwd.Length; i++)
            {
                xored[i] = (byte)(pwd[i] ^ seed[i % seed.Length]);
            }
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(pem);
                return rsa.Encrypt(xored, RSAEncryptionPadding.OaepSHA1);
            }
        }

        // ===================== 包收发 =====================

        private void SendPacket(byte[] payload)
        {
            seq++;
            byte[] pkt = new byte[payload.Length + 4];
            pkt[0] = (byte)payload.Length; pkt[1] = (byte)(payload.Length >> 8); pkt[2] = (byte)(payload.Length >> 16);
            pkt[3] = (byte)(seq & 0xFF);
            Buffer.BlockCopy(payload, 0, pkt, 4, payload.Length);
            sock.Send(pkt);
        }

        private byte[] RecvPacket()
        {
            byte[] hdr = ReadExact(4);
            int len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16);
            seq = hdr[3];
            return ReadExact(len);
        }

        private byte[] ReadExact(int n)
        {
            byte[] buf = new byte[n];
            int got = 0;
            while (got < n)
            {
                int r = sock.Receive(buf, got, n - got, SocketFlags.None);
                if (r <= 0)
                {
                    throw new EndOfStreamException("连接被服务端关闭");
                }
                got += r;
            }
            return buf;
        }

        // ===================== 工具 =====================

        internal sealed class MySqlAuthException : Exception
        {
            public readonly int Code;
            public MySqlAuthException(int code, string msg) : base(code + ": " + msg)
            {
                Code = code;
            }
        }

        private static void ThrowErr(byte[] resp)
        {
            int code = resp.Length >= 3 ? resp[1] | (resp[2] << 8) : 0;
            string msg = resp.Length > 9 && resp[3] == (byte)'#'
                ? Encoding.UTF8.GetString(resp, 9, resp.Length - 9)
                : Encoding.UTF8.GetString(resp, 3, resp.Length - 3);
            throw new MySqlAuthException(code, msg);
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length];
            for (int i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ b[i]);
            return r;
        }

        private static byte[] TrimZero(byte[] data)
        {
            int n = data.Length;
            while (n > 0 && data[n - 1] == 0) n--;
            byte[] r = new byte[n];
            Buffer.BlockCopy(data, 0, r, 0, n);
            return r;
        }

        private static void W4LE(MemoryStream ms, int v)
        {
            ms.WriteByte((byte)v); ms.WriteByte((byte)(v >> 8));
            ms.WriteByte((byte)(v >> 16)); ms.WriteByte((byte)(v >> 24));
        }

        private static void WCStr(MemoryStream ms, string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s);
            ms.Write(b, 0, b.Length);
            ms.WriteByte(0);
        }

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (var p in parts) total += p.Length;
            byte[] r = new byte[total];
            int off = 0;
            foreach (var p in parts)
            {
                Buffer.BlockCopy(p, 0, r, off, p.Length);
                off += p.Length;
            }
            return r;
        }
    }
}
