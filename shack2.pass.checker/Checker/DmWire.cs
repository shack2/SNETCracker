using System;
using System.IO;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// 达梦 DM8 最小客户端：仅实现弱口令检测所需的能力 ——
    /// AUTH_SECURITY 握手（type 200）+ 512 位 DH 密钥交换 + DES-CFB 口令加密的登录消息（type 1）。
    /// 替代达梦官方驱动（DmProvider 数 MB）。零第三方依赖、AOT 安全。
    /// 协议结构参考达梦官方 Go 驱动（dm-go-driver，gitee.com/chunanyong/dm）与 disql 抓包验证。
    /// 覆盖：DM8（8.1.x）登录口令验证。不支持：SSL 登录、等保通信加密（COMM_ENCRYPT_NAME）、
    /// AES 口令加密（仅 DES_CFB，服务端缺省即此）、查询执行。
    /// </summary>
    internal sealed class DmWire : IDisposable
    {
        // 消息头（64 字节）偏移
        private const int HEADER_SIZE = 64;
        private const int OFF_STMT_ID = 0;   // int32，客户端固定 -1
        private const int OFF_MSG_TYPE = 4;  // int16：200=AUTH_SECURITY 1=LOGIN
        private const int OFF_BODY_LEN = 6;  // int32 = 总长 - 64
        private const int OFF_RETCODE = 10;  // int32，<0 为服务端错误（如 -2501 口令无效）
        private const int OFF_XOR = 19;      // byte = 头 0..18 的 XOR 校验

        private const short MSG_AUTH_SECURITY = 200;
        private const short MSG_LOGIN = 1;

        // 口令加密算法 ID
        private const int DES_CFB = 132;     // DES(0x80) | CFB(0x04)

        // 512 位 DH 参数（达梦登录密钥交换固定参数）
        private const string DH_P_HEX =
            "C009D877BAF5FAF416B7F778E6115DCB90D65217DCC2F08A9DFCB5A192C593EBAB02929266B8DBFC2021039FDBD4B7FDE2B996E00008F57AE6EFB4ED3F17B6D3";
        private static readonly byte[] DefaultIV = { 0x20, 0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };

        private Socket sock;

        /// <summary>服务端版本（AUTH_SECURITY 应答中的版本串）。</summary>
        public string ServerVersion = "";

        /// <summary>实例名（登录成功应答中的 InstanceName）。</summary>
        public string InstanceName = "";

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

        /// <summary>认证；口令错误返回 false（error 为服务端错误文本），网络/协议异常直接抛出。</summary>
        public bool Login(string user, string password, out string error)
        {
            error = null;

            // ---- 第一轮：AUTH_SECURITY，换服务端版本/加密算法/服务端 DH 公钥 ----
            BigInteger p = BigInteger.Parse("0" + DH_P_HEX, System.Globalization.NumberStyles.HexNumber);
            BigInteger clientX = RandomBelow(p);
            BigInteger clientY = BigInteger.ModPow(5, clientX, p);
            SendAuthSecurity(clientY);

            int encryptType, hashType;
            byte[] serverPub;
            ReadAuthSecurityReply(out encryptType, out serverPub, out hashType);

            // ---- DH 计算会话密钥，导出口令加密器 ----
            BigInteger serverY = BytesToBigIntUnsigned(serverPub);
            if (serverY.Sign <= 0 || serverY.CompareTo(p) >= 0)
            {
                throw new Exception("服务端 DH 公钥越界");
            }
            byte[] sessionKey = ToMinimalBytes(BigInteger.ModPow(serverY, clientX, p));
            if (encryptType == -1)
            {
                encryptType = DES_CFB; // 服务端未指定时缺省 DES_CFB（与官方驱动一致）
            }
            if (encryptType != DES_CFB)
            {
                throw new Exception("不支持的口令加密算法 ID: " + encryptType);
            }

            // ---- 第二轮：LOGIN（口令密文与明文等长，DES-CFB 流模式无填充） ----
            byte[] encUser = DesCfbCrypt(sessionKey, Encoding.UTF8.GetBytes(user));
            byte[] encPwd = DesCfbCrypt(sessionKey, Encoding.UTF8.GetBytes(password));
            SendLogin(encUser, encPwd);

            // ---- 读登录应答 ----
            byte[] body = ReadMessage(out short msgType, out int retCode);
            int pos = ReadMessageBlock(body, out string blockMsg);
            if (retCode == 0)
            {
                InstanceName = ReadLenString(body, ref pos); // 应答首个字符串为实例名
                return true;
            }
            // 口令无效（-2501）等认证失败：正常失败
            error = retCode + ": " + blockMsg;
            return false;
        }

        /// <summary>取服务端标识用于 Banner 展示。</summary>
        public string Banner()
        {
            string v = ServerVersion.Length > 0 ? "DM " + ServerVersion : "DM8";
            return InstanceName.Length > 0 ? v + " (" + InstanceName + ")" : v;
        }

        public void Dispose()
        {
            try { sock?.Close(); } catch { }
        }

        // ===================== 第一轮：AUTH_SECURITY =====================

        private void SendAuthSecurity(BigInteger clientY)
        {
            var body = new MemoryStream();
            WriteLenString(body, "8.1.2.128");       // 客户端版本（按 disql 8.1.2.x 上报）
            body.WriteByte(0);                       // uKey 标志
            byte[] pub = ToFixedBytes(clientY, 64);  // 客户端 DH 公钥，定长 64 字节
            WriteLenBytes(body, pub);
            Send(MSG_AUTH_SECURITY, body.ToArray(), w =>
            {
                WriteInt32(w, 20, 0);                // sqlcode 占位
                WriteInt32(w, 24, 2);                // compress（与 disql 一致：2）
                w[28] = 1; w[29] = 2;                // loginEncrypt 标志对
                w[30] = 2;                           // 非 BDTA_RS
                w[31] = 1;                           // compressID
                w[32] = 0; w[33] = 0; w[34] = 1;
                WriteInt16(w, 35, 6);                // MsgVersion
            });
        }

        private void ReadAuthSecurityReply(out int encryptType, out byte[] serverPub, out int hashType)
        {
            byte[] body = ReadMessage(out short msgType, out int retCode);
            if (retCode != 0)
            {
                throw new Exception("AUTH_SECURITY 被拒绝: " + retCode + " " + ReadMessageBlock(body, out _));
            }

            // 应答体前缀为消息块（3 个长度跳过段 + 1 个字符串），成功时通常全零
            int pos = ReadMessageBlock(body, out _);

            // 头区内字段（服务端值在固定偏移）
            byte[] header = lastHeader;
            if (Environment.GetEnvironmentVariable("DM_DEBUG") == "1")
            {
                Console.WriteLine("[DmWire] retCode=" + retCode + " bodyLen=" + body.Length);
                Console.WriteLine("[DmWire] header=" + BitConverter.ToString(header));
                Console.WriteLine("[DmWire] body=" + BitConverter.ToString(body));
            }
            int sslEncrypt = ReadInt32(header, 20);
            if (sslEncrypt != 0)
            {
                throw new Exception("服务端要求 SSL 登录（sslEncrypt=" + sslEncrypt + "），不支持");
            }
            int pubKeyFlag = header[40];             // dm904：是否携带 DH 公钥
            int encryptFlag = header[41];            // dm905：是否携带加密算法（2=另带 hashType）

            ServerVersion = ReadLenString(body, ref pos);
            encryptType = -1;
            serverPub = null;
            hashType = -1;
            if (encryptFlag > 0)
            {
                encryptType = ReadInt32(body, pos); pos += 4;
            }
            if (pubKeyFlag > 0)
            {
                serverPub = ReadLenBytes(body, ref pos);
                pos += 16;                            // 公钥后随 16 字节 MD5 摘要，跳过
            }
            if (encryptFlag == 2 && pos + 4 <= body.Length)
            {
                hashType = ReadInt32(body, pos);
            }
            if (serverPub == null || serverPub.Length == 0)
            {
                throw new Exception("服务端未下发 DH 公钥（可能关闭了口令加密登录）");
            }
        }

        // ===================== 第二轮：LOGIN =====================

        private void SendLogin(byte[] encUser, byte[] encPwd)
        {
            var body = new MemoryStream();
            WriteLenBytes(body, encUser);
            WriteLenBytes(body, encPwd);
            WriteLenString(body, "SNETCracker");
            WriteLenString(body, "Windows");
            WriteLenString(body, Environment.MachineName);
            body.WriteByte(0);                        // rwStandby
            body.WriteByte(0); body.WriteByte(0);     // serverOption（空，uint16 长度前缀）
            Send(MSG_LOGIN, body.ToArray(), w =>
            {
                WriteInt32(w, 20, 1);                 // clientType
                WriteInt32(w, 24, 1);                 // isoLevel
                WriteInt32(w, 28, 1);                 // locale
                w[32] = 0x00; w[33] = 0xe0;           // localTimezone（按 disql 抓包值）
                w[34] = 1;                            // 读写模式
                WriteInt32(w, 35, 0);                 // sessionTimeout
                w[39] = 0; w[40] = 0;                 // mppLocal / rwSeparate
                w[41] = 1;                            // newLobFlag
                w[42] = 0;                            // osAuthType
            });
        }

        // ===================== 消息收发 =====================

        private byte[] lastHeader;

        private void Send(short msgType, byte[] body, Action<byte[]> fillHeader)
        {
            byte[] pkt = new byte[HEADER_SIZE + body.Length];
            WriteInt32(pkt, OFF_STMT_ID, -1);
            WriteInt16(pkt, OFF_MSG_TYPE, msgType);
            WriteInt32(pkt, OFF_BODY_LEN, body.Length);
            fillHeader(pkt);
            byte xor = 0;
            for (int i = 0; i < OFF_XOR; i++) xor ^= pkt[i];
            pkt[OFF_XOR] = xor;
            Buffer.BlockCopy(body, 0, pkt, HEADER_SIZE, body.Length);
            sock.Send(pkt);
        }

        private byte[] ReadMessage(out short msgType, out int retCode)
        {
            byte[] header = ReadExact(HEADER_SIZE);
            lastHeader = header;
            msgType = (short)(header[OFF_MSG_TYPE] | (header[OFF_MSG_TYPE + 1] << 8));
            retCode = ReadInt32(header, OFF_RETCODE);
            int bodyLen = ReadInt32(header, OFF_BODY_LEN);
            if (bodyLen < 0 || bodyLen > 16 * 1024 * 1024)
            {
                throw new Exception("应答长度异常: " + bodyLen);
            }
            return bodyLen > 0 ? ReadExact(bodyLen) : new byte[0];
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

        // ===================== 口令加密（DES-CFB-64，IV 固定） =====================

        /// <summary>
        /// DES-CFB-64 加密： keystream = DES_ECB(前一密文分组)，逐分组与明文异或。
        /// .NET 的 DES 仅支持 CFB-8，故手工实现 CFB-64（与 Go cipher.NewCFBEncrypter 等价）。
        /// </summary>
        private static byte[] DesCfbCrypt(byte[] sessionKey, byte[] plain)
        {
            byte[] key = new byte[8];
            Buffer.BlockCopy(sessionKey, 0, key, 0, Math.Min(8, sessionKey.Length));
            using (DES des = DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                using (ICryptoTransform ecb = des.CreateEncryptor(key, null))
                {
                    byte[] ret = new byte[plain.Length];
                    byte[] state = (byte[])DefaultIV.Clone();
                    int off = 0;
                    while (off < plain.Length)
                    {
                        byte[] ks = new byte[8];
                        ecb.TransformBlock(state, 0, 8, ks, 0);   // keystream 分组
                        int n = Math.Min(8, plain.Length - off);
                        for (int i = 0; i < n; i++)
                        {
                            ret[off + i] = (byte)(plain[off + i] ^ ks[i]);
                        }
                        if (n == 8)
                        {
                            Buffer.BlockCopy(ret, off, state, 0, 8); // CFB：密文反馈
                        }
                        off += n;
                    }
                    return ret;
                }
            }
        }

        // ===================== 编解码工具（全部小端） =====================

        private static void WriteInt16(byte[] w, int off, int v)
        {
            w[off] = (byte)v;
            w[off + 1] = (byte)(v >> 8);
        }

        private static void WriteInt32(byte[] w, int off, int v)
        {
            w[off] = (byte)v;
            w[off + 1] = (byte)(v >> 8);
            w[off + 2] = (byte)(v >> 16);
            w[off + 3] = (byte)(v >> 24);
        }

        private static int ReadInt32(byte[] r, int off)
        {
            return r[off] | (r[off + 1] << 8) | (r[off + 2] << 16) | (r[off + 3] << 24);
        }

        private static void WriteLenString(Stream s, string str)
        {
            WriteLenBytes(s, Encoding.UTF8.GetBytes(str));
        }

        private static void WriteLenBytes(Stream s, byte[] data)
        {
            byte[] len = new byte[4];
            WriteInt32(len, 0, data.Length);
            s.Write(len, 0, 4);
            s.Write(data, 0, data.Length);
        }

        private static string ReadLenString(byte[] body, int pos)
        {
            int p = pos;
            return ReadLenString(body, ref p);
        }

        /// <summary>读应答体前缀的消息块（3 个长度跳过段 + 1 个字符串），返回业务负载起始偏移。</summary>
        private static int ReadMessageBlock(byte[] body, out string msg)
        {
            msg = "";
            int pos = 0;
            for (int i = 0; i < 3; i++)
            {
                if (pos + 4 > body.Length) { return body.Length; }
                int skip = ReadInt32(body, pos);
                if (skip < 0 || pos + 4 + skip > body.Length) { msg = ""; return 0; } // 布局不符，回退从头解析
                pos += 4 + skip;
            }
            msg = ReadLenString(body, ref pos);
            return pos;
        }

        private static string ReadLenString(byte[] body, ref int pos)
        {
            if (pos + 4 > body.Length) return "";
            int len = ReadInt32(body, pos);
            pos += 4;
            if (len == 0) return "";                       // 空串：仅消耗 4 字节长度前缀
            if (len < 0 || pos + len > body.Length) { pos = body.Length; return ""; }
            string s = Encoding.UTF8.GetString(body, pos, len);
            pos += len;
            return s;
        }

        private static byte[] ReadLenBytes(byte[] body, ref int pos)
        {
            if (pos + 4 > body.Length) return new byte[0];
            int len = ReadInt32(body, pos);
            pos += 4;
            if (len <= 0 || pos + len > body.Length) { pos = body.Length; return new byte[0]; }
            byte[] r = new byte[len];
            Buffer.BlockCopy(body, pos, r, 0, len);
            pos += len;
            return r;
        }

        // ===================== 大数（DH） =====================

        private static BigInteger RandomBelow(BigInteger p)
        {
            byte[] buf = new byte[64];
            BigInteger x;
            do
            {
                RandomNumberGenerator.Fill(buf);
                x = BytesToBigIntUnsigned(buf) % p;
            } while (x.Sign == 0);
            return x;
        }

        private static BigInteger BytesToBigIntUnsigned(byte[] be)
        {
            byte[] copy = (byte[])be.Clone();
            Array.Reverse(copy);
            byte[] le = new byte[copy.Length + 1]; // 末位补 0 保证无符号
            Buffer.BlockCopy(copy, 0, le, 0, copy.Length);
            return new BigInteger(le);
        }

        private static byte[] ToMinimalBytes(BigInteger v)
        {
            byte[] le = v.ToByteArray();           // 小端、可能带符号补零
            int n = le.Length;
            while (n > 1 && le[n - 1] == 0) n--;   // 去高位零 → 最小无符号表示
            byte[] be = new byte[n];
            for (int i = 0; i < n; i++) be[i] = le[n - 1 - i];
            return be;
        }

        private static byte[] ToFixedBytes(BigInteger v, int len)
        {
            byte[] minimal = ToMinimalBytes(v);
            byte[] r = new byte[len];
            int copy = Math.Min(len, minimal.Length);
            Buffer.BlockCopy(minimal, minimal.Length - copy, r, len - copy, copy);
            return r;
        }
    }
}
