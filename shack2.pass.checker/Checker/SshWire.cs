using System;
using System.IO;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// SSH 最小客户端：仅实现弱口令检测所需的能力 ——
    /// 版本横幅交换 + 算法协商 + 密钥交换（curve25519-sha256 / ecdh-sha2-nistp256 / diffie-hellman-group14-sha256）
    /// + AES-CTR/CBC、3DES-CBC/hmac-sha2-256 传输层 + userauth password 认证。
    /// 替代 SSH.NET + BouncyCastle（合计约 5.7 MB IL）。
    /// 协议参考 RFC 4251/4252/4253/4256、RFC 4344（CTR/CBC）、RFC 5656（ECDH）、RFC 3526（DH group14）、RFC 7748/8731（Curve25519）。
    /// 零第三方依赖、AOT 安全。不校验服务端主机密钥签名（弱口令场景无意义）。
    /// 支持同一连接上连续多次 password 认证（Handshake 后反复 TryPassword）；
    /// 服务端按 MaxAuthTries 等策略主动断开时返回 Closed，由调用方重连继续。
    /// 不支持：公钥认证、rekey、压缩。
    /// </summary>
    internal sealed class SshWire : IDisposable
    {
        private const byte MsgDisconnect = 1, MsgIgnore = 2, MsgDebug = 4;
        private const byte MsgServiceRequest = 5, MsgServiceAccept = 6;
        private const byte MsgKexInit = 20, MsgNewKeys = 21, MsgKexInit30 = 30, MsgKexReply31 = 31;
        private const byte MsgUserAuthRequest = 50, MsgUserAuthFailure = 51, MsgUserAuthSuccess = 52, MsgUserAuthBanner = 53;
        private const byte MsgUserAuthInfoRequest = 60, MsgUserAuthInfoResponse = 61;
        private const byte MsgGlobalRequest = 80, MsgRequestFailure = 82;

        private const string KexCurve25519 = "curve25519-sha256";
        private const string KexEcdhP256 = "ecdh-sha2-nistp256";
        private const string KexDhG14 = "diffie-hellman-group14-sha256";
        private static readonly string[] CipherNames =
        {
            "aes256-ctr", "aes192-ctr", "aes128-ctr",
            "aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc"
        };

        private Socket sock;
        private uint seqC2S, seqS2C;
        private ISshCipher encC2S, decS2C;
        private HMACSHA256 macC2S, macS2C;

        /// <summary>服务端版本横幅（如 SSH-2.0-OpenSSH_9.6p1）。</summary>
        public string ServerBanner = "";

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

        /// <summary>最近一次认证失败（MsgUserAuthFailure）时服务端声明可继续的认证方法列表（RFC 4252 §5.1）。</summary>
        public string[] ContinueMethods { get; private set; }

        /// <summary>服务端是否允许指定认证方法（依据最近一次失败的 auth-list；未收到过失败响应时视为允许）。</summary>
        public bool MethodAllowed(string method)
        {
            if (ContinueMethods == null)
            {
                return true;
            }
            foreach (string m in ContinueMethods)
            {
                if (string.Equals(m, method, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>完整流程：握手 + 一次密码认证（兼容旧单任务调用）；
        /// 服务端不支持 password 时自动降级 keyboard-interactive。
        /// 口令错误返回 false；网络/协议异常直接抛出。</summary>
        public bool Login(string user, string password)
        {
            Handshake();
            AuthResult r = TryPassword(user, password);
            if (r == AuthResult.Failed && !MethodAllowed("password") && MethodAllowed("keyboard-interactive"))
            {
                r = TryKeyboardInteractive(user, password);
            }
            if (r == AuthResult.Closed)
            {
                throw new EndOfStreamException("认证过程中连接被服务端关闭");
            }
            return r == AuthResult.Success;
        }

        /// <summary>握手：版本横幅 + 算法协商 + 密钥交换 + 激活 userauth 服务。
        /// 之后可在同一连接上反复调用 TryPassword。网络/协议异常直接抛出。</summary>
        public void Handshake()
        {
            // 1) 版本横幅
            string clientBanner = "SSH-2.0-SPasswordChecker_2.0";
            byte[] sendLine = Encoding.ASCII.GetBytes(clientBanner + "\r\n");
            sock.Send(sendLine);
            ServerBanner = ReadBannerLine();

            // 2) 算法协商 + 密钥交换
            byte[] icPayload = BuildKexInit();
            SendPacket(icPayload);
            byte[] isPayload = ExpectPacket(MsgKexInit);
            KexInitInfo srv = ParseKexInit(isPayload);

            // RFC 4253 §7.1：以客户端列表顺序为准，取服务端也支持的第一个
            string kex = srv.Kex.IndexOf(KexCurve25519, StringComparison.Ordinal) >= 0 ? KexCurve25519
                       : srv.Kex.IndexOf(KexEcdhP256, StringComparison.Ordinal) >= 0 ? KexEcdhP256
                       : srv.Kex.IndexOf(KexDhG14, StringComparison.Ordinal) >= 0 ? KexDhG14
                       : throw new Exception("服务端不支持可用的密钥交换算法");
            // 服务端声明 follows 且猜错（其首选非我方首选 curve25519）→ 丢弃其猜测包
            if (srv.Follows && srv.FirstKex != KexCurve25519)
            {
                RecvPacket();
            }

            byte[] k, h, sessionId;
            if (kex == KexCurve25519)
            {
                sessionId = KexX25519(clientBanner, icPayload, isPayload, out k, out h);
            }
            else if (kex == KexEcdhP256)
            {
                sessionId = KexEcdh(clientBanner, icPayload, isPayload, out k, out h);
            }
            else
            {
                sessionId = KexDhGroup14(clientBanner, icPayload, isPayload, out k, out h);
            }

            string cipherC2S = SelectCipher(srv.CipherC2S);
            string cipherS2C = SelectCipher(srv.CipherS2C);

            // 3) 按协商出的 cipher 派生 IV/密钥（RFC 4253 §7.2）并激活加密
            byte[] ivC = DeriveKey(k, h, 'A', sessionId, CipherBlockSize(cipherC2S));
            byte[] ivS = DeriveKey(k, h, 'B', sessionId, CipherBlockSize(cipherS2C));
            byte[] keyC = DeriveKey(k, h, 'C', sessionId, CipherKeyLength(cipherC2S));
            byte[] keyS = DeriveKey(k, h, 'D', sessionId, CipherKeyLength(cipherS2C));
            byte[] macKC = DeriveKey(k, h, 'E', sessionId, 32);
            byte[] macKS = DeriveKey(k, h, 'F', sessionId, 32);

            SendPacket(new byte[] { MsgNewKeys });
            encC2S = CreateCipher(cipherC2S, keyC, ivC, true);
            macC2S = new HMACSHA256(macKC);
            ExpectPacket(MsgNewKeys);
            decS2C = CreateCipher(cipherS2C, keyS, ivS, false);
            macS2C = new HMACSHA256(macKS);

            // 4) userauth 服务
            var sw = new SshWriter();
            sw.W8(MsgServiceRequest); sw.WString("ssh-userauth");
            SendPacket(sw.Bytes());
            ExpectPacket(MsgServiceAccept);
        }

        /// <summary>在同一连接上执行一次 password 认证（RFC 4252 允许连续发起）。
        /// Success=口令正确；Failed=口令错误（含用户不存在）；
        /// Closed=服务端主动断开（如达到 MaxAuthTries）或连接失效，调用方应 Dispose 后重连重试。
        /// 其他协议异常直接抛出。</summary>
        public AuthResult TryPassword(string user, string password)
        {
            var aw = new SshWriter();
            aw.W8(MsgUserAuthRequest);
            aw.WString(Encoding.UTF8.GetBytes(user));
            aw.WString("ssh-connection");
            aw.WString("password");
            aw.W8(0);
            aw.WString(Encoding.UTF8.GetBytes(password));

            try
            {
                SendPacket(aw.Bytes());
                for (; ; )
                {
                    byte[] resp = RecvPacket();
                    if (resp.Length == 0) throw new Exception("SSH 空包");
                    switch (resp[0])
                    {
                        case MsgUserAuthSuccess:
                            return AuthResult.Success;
                        case MsgUserAuthFailure:
                            ContinueMethods = ParseNameList(resp); // 记录可继续方法，供降级判断
                            return AuthResult.Failed; // 口令错误（含用户不存在），正常失败
                        case MsgUserAuthBanner:
                        case MsgIgnore:
                        case MsgDebug:
                            continue;
                        case MsgGlobalRequest:
                            SendPacket(new byte[] { MsgRequestFailure });
                            continue;
                        case MsgDisconnect:
                            return AuthResult.Closed; // 服务端按策略断开（MaxAuthTries 等）
                        default:
                            throw new Exception("SSH 认证阶段响应类型异常: " + resp[0]);
                    }
                }
            }
            catch (EndOfStreamException)
            {
                return AuthResult.Closed;
            }
            catch (SocketException)
            {
                return AuthResult.Closed; // RST / 收发超时：连接已不可用，统一走重连
            }
        }

        /// <summary>keyboard-interactive 认证（RFC 4256）：PAM 场景的挑战-应答，FreeBSD/网络设备常只开此项。
        /// 弱口令场景策略：echo=false 的 prompt 回密码，echo=true 回空串；支持多轮 INFO_REQUEST。
        /// 返回值语义与 TryPassword 一致。</summary>
        public AuthResult TryKeyboardInteractive(string user, string password)
        {
            var aw = new SshWriter();
            aw.W8(MsgUserAuthRequest);
            aw.WString(Encoding.UTF8.GetBytes(user));
            aw.WString("ssh-connection");
            aw.WString("keyboard-interactive");
            aw.WString(""); // lang
            aw.WString(""); // submethods

            try
            {
                SendPacket(aw.Bytes());
                for (; ; )
                {
                    byte[] resp = RecvPacket();
                    if (resp.Length == 0) throw new Exception("SSH 空包");
                    switch (resp[0])
                    {
                        case MsgUserAuthSuccess:
                            return AuthResult.Success;
                        case MsgUserAuthFailure:
                            ContinueMethods = ParseNameList(resp);
                            return AuthResult.Failed;
                        case MsgUserAuthInfoRequest:
                            SendPacket(BuildInfoResponse(resp, password));
                            continue;
                        case MsgUserAuthBanner:
                        case MsgIgnore:
                        case MsgDebug:
                            continue;
                        case MsgGlobalRequest:
                            SendPacket(new byte[] { MsgRequestFailure });
                            continue;
                        case MsgDisconnect:
                            return AuthResult.Closed;
                        default:
                            throw new Exception("SSH 认证阶段响应类型异常: " + resp[0]);
                    }
                }
            }
            catch (EndOfStreamException)
            {
                return AuthResult.Closed;
            }
            catch (SocketException)
            {
                return AuthResult.Closed;
            }
        }

        /// <summary>解析 INFO_REQUEST（60）的 prompts，构造 INFO_RESPONSE（61）：
        /// echo=false 的 prompt 回密码，echo=true（如 OTP 提示）回空串。</summary>
        private static byte[] BuildInfoResponse(byte[] req, string password)
        {
            int pos = 1;
            pos = SkipString(req, pos); // name
            pos = SkipString(req, pos); // instruction
            pos = SkipString(req, pos); // lang
            int num = (req[pos] << 24) | (req[pos + 1] << 16) | (req[pos + 2] << 8) | req[pos + 3];
            pos += 4;
            bool[] echoes = new bool[num];
            for (int i = 0; i < num; i++)
            {
                pos = SkipString(req, pos); // prompt 文本
                echoes[i] = req[pos] != 0;
                pos += 1;
            }
            var w = new SshWriter();
            w.W8(MsgUserAuthInfoResponse);
            w.W32(num);
            for (int i = 0; i < num; i++)
            {
                w.WString(echoes[i] ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(password));
            }
            return w.Bytes();
        }

        private static int SkipString(byte[] d, int pos)
        {
            int len = (d[pos] << 24) | (d[pos + 1] << 16) | (d[pos + 2] << 8) | d[pos + 3];
            return pos + 4 + len;
        }

        /// <summary>解析 MsgUserAuthFailure payload：string auth-list + bool partial-success。</summary>
        private static string[] ParseNameList(byte[] resp)
        {
            try
            {
                int len = (resp[1] << 24) | (resp[2] << 16) | (resp[3] << 8) | resp[4];
                string list = Encoding.ASCII.GetString(resp, 5, Math.Min(len, resp.Length - 5));
                return list.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>取服务端标识用于 Banner 展示。</summary>
        public string Banner()
        {
            return ServerBanner.Length > 0 ? ServerBanner : "SSH";
        }

        public void Dispose()
        {
            try
            {
                if (sock != null && sock.Connected)
                {
                    var w = new SshWriter();
                    w.W8(MsgDisconnect); w.W32(11); // SSH_DISCONNECT_BY_APPLICATION
                    w.WString(""); w.WString("");
                    SendPacket(w.Bytes());
                }
            }
            catch { }
            try { sock?.Close(); } catch { }
            encC2S?.Dispose(); decS2C?.Dispose();
            macC2S?.Dispose(); macS2C?.Dispose();
        }

        // ===================== 密钥交换 =====================

        private byte[] KexEcdh(string clientBanner, byte[] ic, byte[] is2, out byte[] sharedMp, out byte[] h)
        {
            // 自实现 P-256 标量乘：.NET 的 ECDiffieHellman 在 Windows 上默认过 SHA256 KDF、
            // 在 Linux 上返回裸密钥，行为不一致；手写 ECC 保证跨平台与线格式一致。
            BigInteger d;
            do { d = new BigInteger(RandomBytes(32), true, true); }
            while (d.Sign == 0 || d.CompareTo(P256.N) >= 0);
            BigInteger[] myPub = P256.ScalarMult(d, P256.G);
            byte[] qc = new byte[65];
            qc[0] = 4;
            Buffer.BlockCopy(P256.To32(myPub[0]), 0, qc, 1, 32);
            Buffer.BlockCopy(P256.To32(myPub[1]), 0, qc, 33, 32);

            var w = new SshWriter();
            w.W8(MsgKexInit30); w.WString(qc);
            SendPacket(w.Bytes());

            byte[] reply = ExpectPacket(MsgKexReply31);
            var r = new SshReader(reply, 1);
            byte[] ks = r.RString();
            byte[] qs = r.RString();
            r.RString(); // 签名：不校验
            if (qs.Length != 65 || qs[0] != 4)
            {
                throw new Exception("ECDH 服务端公钥格式异常");
            }
            BigInteger sx = new BigInteger(Slice(qs, 1, 32), true, true);
            BigInteger sy = new BigInteger(Slice(qs, 33, 32), true, true);
            if (!P256.OnCurve(sx, sy))
            {
                throw new Exception("ECDH 服务端公钥不在曲线上");
            }
            BigInteger[] sharedPt = P256.ScalarMult(d, new[] { sx, sy });
            if (sharedPt == null)
            {
                throw new Exception("ECDH 共享密钥为无穷远点");
            }
            byte[] shared = P256.To32(sharedPt[0]); // 裸 X 坐标（RFC 5653）
            sharedMp = shared;

            h = ExchangeHash(clientBanner, ServerBanner, ic, is2, ks,
                hw => { hw.WString(qc); hw.WString(qs); hw.WMpInt(shared); });
            return h;
        }

        /// <summary>curve25519-sha256 密钥交换（RFC 8731）：X25519 ECDH，消息结构与 ECDH 相同（30/31）。</summary>
        private byte[] KexX25519(string clientBanner, byte[] ic, byte[] is2, out byte[] sharedMp, out byte[] h)
        {
            byte[] priv = RandomBytes(32);
            byte[] basePt = new byte[32];
            basePt[0] = 9; // Curve25519 基点 u=9
            byte[] qc = X25519.ScalarMult(priv, basePt);

            var w = new SshWriter();
            w.W8(MsgKexInit30); w.WString(qc);
            SendPacket(w.Bytes());

            byte[] reply = ExpectPacket(MsgKexReply31);
            var r = new SshReader(reply, 1);
            byte[] ks = r.RString();
            byte[] qs = r.RString();
            r.RString(); // 签名：不校验
            if (qs.Length != 32)
            {
                throw new Exception("Curve25519 服务端公钥长度异常: " + qs.Length);
            }
            byte[] shared = X25519.ScalarMult(priv, qs);
            bool allZero = true;
            foreach (byte b in shared)
            {
                if (b != 0) { allZero = false; break; }
            }
            if (allZero)
            {
                throw new Exception("Curve25519 共享密钥全零（低阶点）");
            }
            // RFC 8731 §3.1：X25519 的 32 字节小端输出【直接按原字节序】重解释为大端整数，
            // 再按 mpint 编码 —— 注意【不要】反转字节序（反转是常见误实现）
            sharedMp = shared;

            h = ExchangeHash(clientBanner, ServerBanner, ic, is2, ks,
                hw => { hw.WString(qc); hw.WString(qs); hw.WMpInt(shared); });
            return h;
        }

        /// <summary>RFC 7748 X25519：Montgomery 阶梯标量乘（BigInteger 实现，一次握手仅两次标量乘，性能足够）。</summary>
        private static class X25519
        {
            private static readonly BigInteger P = (BigInteger.One << 255) - 19;
            private static readonly BigInteger A24 = 121665;

            /// <summary>scalar 与 u 坐标均为 32 字节小端序；scalar 内部按 RFC 7748 clamp。</summary>
            public static byte[] ScalarMult(byte[] scalar, byte[] u)
            {
                byte[] k = (byte[])scalar.Clone();
                k[0] &= 248; k[31] &= 127; k[31] |= 64; // clamp
                byte[] uc = (byte[])u.Clone();
                uc[31] &= 0x7F; // RFC 7748：接收方必须屏蔽 u 坐标最后一字节的最高位
                BigInteger x1 = new BigInteger(uc, true, false); // 小端无符号
                BigInteger x2 = BigInteger.One, z2 = BigInteger.Zero;
                BigInteger x3 = x1, z3 = BigInteger.One;
                int swap = 0;
                for (int t = 254; t >= 0; t--)
                {
                    int kt = (k[t >> 3] >> (t & 7)) & 1;
                    swap ^= kt;
                    if (swap != 0) { BigInteger tmp = x2; x2 = x3; x3 = tmp; tmp = z2; z2 = z3; z3 = tmp; }
                    swap = kt;

                    BigInteger a = Mod(x2 + z2);
                    BigInteger aa = Mod(a * a);
                    BigInteger b = Mod(x2 - z2);
                    BigInteger bb = Mod(b * b);
                    BigInteger e = Mod(aa - bb);
                    BigInteger c = Mod(x3 + z3);
                    BigInteger d = Mod(x3 - z3);
                    BigInteger da = Mod(d * a);
                    BigInteger cb = Mod(c * b);
                    BigInteger daPcb = Mod(da + cb);
                    BigInteger daMcb = Mod(da - cb);
                    x3 = Mod(daPcb * daPcb);
                    z3 = Mod(x1 * Mod(daMcb * daMcb));
                    x2 = Mod(aa * bb);
                    z2 = Mod(e * Mod(aa + A24 * e));
                }
                if (swap != 0) { BigInteger tmp = x2; x2 = x3; x3 = tmp; tmp = z2; z2 = z3; z3 = tmp; }

                BigInteger result = Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
                byte[] le = result.ToByteArray(true, false); // 小端无符号
                byte[] out32 = new byte[32];
                Buffer.BlockCopy(le, 0, out32, 0, Math.Min(le.Length, 32));
                return out32;
            }

            private static BigInteger Mod(BigInteger v)
            {
                v %= P;
                return v.Sign < 0 ? v + P : v;
            }
        }

        /// <summary>NIST P-256 (secp256r1) 仿射点运算，仅供 ECDH 使用。</summary>
        private static class P256
        {
            public static readonly BigInteger P = new BigInteger(FromHex(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"), true, true);
            private static readonly BigInteger A = P - 3;
            private static readonly BigInteger B = new BigInteger(FromHex(
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"), true, true);
            public static readonly BigInteger[] G =
            {
                new BigInteger(FromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"), true, true),
                new BigInteger(FromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"), true, true)
            };
            public static readonly BigInteger N = new BigInteger(FromHex(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"), true, true);

            public static bool OnCurve(BigInteger x, BigInteger y)
            {
                if (x.Sign < 0 || x.CompareTo(P) >= 0 || y.Sign < 0 || y.CompareTo(P) >= 0) return false;
                BigInteger lhs = Mod(y * y);
                BigInteger rhs = Mod(x * x * x + A * x + B);
                return lhs == rhs;
            }

            /// <summary>倍倍加法的标量乘；null 表示无穷远点。</summary>
            public static BigInteger[] ScalarMult(BigInteger k, BigInteger[] pt)
            {
                BigInteger[] r = null;
                BigInteger[] add = pt;
                for (int i = 0; i < 256 && !k.IsZero; i++)
                {
                    if (!k.IsEven) r = Add(r, add);
                    add = Double(add);
                    k >>= 1;
                }
                return r;
            }

            public static byte[] To32(BigInteger v)
            {
                byte[] b = v.ToByteArray(true, true);
                byte[] r = new byte[32];
                Buffer.BlockCopy(b, 0, r, 32 - b.Length, b.Length);
                return r;
            }

            private static BigInteger Mod(BigInteger v)
            {
                v %= P;
                return v.Sign < 0 ? v + P : v;
            }

            private static BigInteger Inv(BigInteger v)
            {
                return BigInteger.ModPow(Mod(v), P - 2, P);
            }

            private static BigInteger[] Add(BigInteger[] p1, BigInteger[] p2)
            {
                if (p1 == null) return p2;
                if (p2 == null) return p1;
                if (p1[0] == p2[0])
                {
                    return p1[1] == p2[1] ? Double(p1) : null; // 同点→倍点，互逆→无穷远
                }
                BigInteger lam = Mod((p2[1] - p1[1]) * Inv(p2[0] - p1[0]));
                BigInteger x3 = Mod(lam * lam - p1[0] - p2[0]);
                BigInteger y3 = Mod(lam * (p1[0] - x3) - p1[1]);
                return new[] { x3, y3 };
            }

            private static BigInteger[] Double(BigInteger[] p1)
            {
                if (p1 == null || p1[1].IsZero) return null;
                BigInteger lam = Mod((3 * p1[0] * p1[0] + A) * Inv(2 * p1[1]));
                BigInteger x3 = Mod(lam * lam - 2 * p1[0]);
                BigInteger y3 = Mod(lam * (p1[0] - x3) - p1[1]);
                return new[] { x3, y3 };
            }
        }

        // RFC 3526 group14（2048 位 MODP）
        private const string G14Hex =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

        private byte[] KexDhGroup14(string clientBanner, byte[] ic, byte[] is2, out byte[] sharedMp, out byte[] h)
        {
            BigInteger p = new BigInteger(FromHex(G14Hex), true, true);
            byte[] xBytes = RandomBytes(32);
            BigInteger x = new BigInteger(xBytes, true, true);
            BigInteger e = BigInteger.ModPow(2, x, p); // 客户端公钥

            var w = new SshWriter();
            w.W8(MsgKexInit30); w.WMpInt(e);
            SendPacket(w.Bytes());

            byte[] reply = ExpectPacket(MsgKexReply31);
            var r = new SshReader(reply, 1);
            byte[] ks = r.RString();
            BigInteger f = r.RMpInt();
            r.RString(); // 签名：不校验
            BigInteger one = BigInteger.One;
            if (f.CompareTo(one) <= 0 || f.CompareTo(p - one) >= 0)
            {
                throw new Exception("DH 服务端公钥越界");
            }
            BigInteger kBig = BigInteger.ModPow(f, x, p);
            sharedMp = kBig.ToByteArray(true, true);

            h = ExchangeHash(clientBanner, ServerBanner, ic, is2, ks,
                hw => { hw.WMpInt(e); hw.WMpInt(f); hw.WMpInt(kBig); });
            return h;
        }

        private static byte[] ExchangeHash(string vc, string vs, byte[] ic, byte[] is2, byte[] ks, Action<SshWriter> tail)
        {
            var w = new SshWriter();
            w.WString(Encoding.ASCII.GetBytes(vc));
            w.WString(Encoding.ASCII.GetBytes(vs));
            w.WString(ic);
            w.WString(is2);
            w.WString(ks);
            tail(w);
            return SHA256.HashData(w.Bytes());
        }

        private static byte[] DeriveKey(byte[] k, byte[] h, char letter, byte[] sessionId, int need)
        {
            // HASH(K || H || letter || session_id)，不足则 HASH(K || H || K1) 扩展
            var w = new SshWriter();
            w.WMpInt(k);
            byte[] kMp = w.Bytes();
            byte[] input = Concat(kMp, h, new[] { (byte)letter }, sessionId);
            byte[] output = SHA256.HashData(input);
            while (output.Length < need)
            {
                byte[] more = SHA256.HashData(Concat(kMp, h, output));
                output = Concat(output, more);
            }
            byte[] r = new byte[need];
            Buffer.BlockCopy(output, 0, r, 0, need);
            return r;
        }

        // ===================== KEXINIT =====================

        private sealed class KexInitInfo
        {
            public string Kex = "", FirstKex = "", CipherC2S = "", CipherS2C = "";
            public bool Follows;
        }

        private static byte[] BuildKexInit()
        {
            var w = new SshWriter();
            w.W8(MsgKexInit);
            w.WBytes(RandomBytes(16));
            w.WString(KexCurve25519 + "," + KexEcdhP256 + "," + KexDhG14);   // kex（客户端顺序即优先级）
            w.WString("ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,rsa-sha2-512,ssh-rsa"); // hostkey
            string ciphers = string.Join(",", CipherNames);
            w.WString(ciphers); w.WString(ciphers);                        // cipher
            w.WString("hmac-sha2-256"); w.WString("hmac-sha2-256");        // mac
            w.WString("none"); w.WString("none");                          // compression
            w.WString(""); w.WString("");                                  // languages
            w.W8(0);                                                       // first_kex_packet_follows = false
            w.W32(0);
            return w.Bytes();
        }

        private static KexInitInfo ParseKexInit(byte[] payload)
        {
            var r = new SshReader(payload, 17); // 跳过类型 + cookie
            var info = new KexInitInfo();
            info.Kex = Encoding.ASCII.GetString(r.RString());
            info.FirstKex = info.Kex.Split(',')[0];
            r.RString(); // host key algorithms
            info.CipherC2S = Encoding.ASCII.GetString(r.RString());
            info.CipherS2C = Encoding.ASCII.GetString(r.RString());
            for (int i = 0; i < 6; i++) r.RString(); // MAC + compression + languages
            info.Follows = r.R8() != 0;
            return info;
        }

        private static string SelectCipher(string serverOffers)
        {
            string[] offered = serverOffers.Split(',');
            foreach (string candidate in CipherNames)
            {
                foreach (string server in offered)
                {
                    if (string.Equals(candidate, server, StringComparison.Ordinal)) return candidate;
                }
            }
            throw new Exception("服务端不支持可用的加密算法；客户端提供 " + string.Join(",", CipherNames)
                + "；服务端提供 " + serverOffers);
        }

        private static int CipherKeyLength(string name)
        {
            if (name.StartsWith("aes128-", StringComparison.Ordinal)) return 16;
            if (name.StartsWith("aes192-", StringComparison.Ordinal)) return 24;
            return 24 + (name.StartsWith("aes256-", StringComparison.Ordinal) ? 8 : 0); // AES-256=32，3DES=24
        }

        private static int CipherBlockSize(string name)
        {
            return name == "3des-cbc" ? 8 : 16;
        }

        // ===================== 包收发 =====================

        private void SendPacket(byte[] payload)
        {
            int bs = encC2S != null ? encC2S.BlockSize : 8;
            int pad = bs - ((payload.Length + 5) % bs);
            if (pad < 4) pad += bs;
            int pktLen = payload.Length + 1 + pad;
            byte[] plain = new byte[4 + pktLen];
            plain[0] = (byte)(pktLen >> 24); plain[1] = (byte)(pktLen >> 16);
            plain[2] = (byte)(pktLen >> 8); plain[3] = (byte)pktLen;
            plain[4] = (byte)pad;
            Buffer.BlockCopy(payload, 0, plain, 5, payload.Length);
            byte[] rnd = RandomBytes(pad);
            Buffer.BlockCopy(rnd, 0, plain, 5 + payload.Length, pad);

            byte[] mac = null;
            if (macC2S != null)
            {
                byte[] seqb = { (byte)(seqC2S >> 24), (byte)(seqC2S >> 16), (byte)(seqC2S >> 8), (byte)seqC2S };
                mac = macC2S.ComputeHash(Concat(seqb, plain));
            }
            if (encC2S != null) encC2S.Transform(plain, 0, plain.Length);
            sock.Send(plain);
            if (mac != null) sock.Send(mac);
            seqC2S++;
        }

        private byte[] RecvPacket()
        {
            // CBC 必须按完整块解密；CTR 也可复用同一分块读取逻辑。
            int bs = decS2C != null ? decS2C.BlockSize : 8;
            byte[] first = ReadExact(bs);
            if (decS2C != null) decS2C.Transform(first, 0, first.Length);
            int pktLen = (first[0] << 24) | (first[1] << 16) | (first[2] << 8) | first[3];
            if (pktLen < 1 || pktLen > 1024 * 1024 || pktLen + 4 < bs)
            {
                throw new Exception("SSH 包长度非法: " + pktLen);
            }
            byte[] rest = ReadExact(pktLen + 4 - bs);
            if (decS2C != null) decS2C.Transform(rest, 0, rest.Length);
            byte[] plain = Concat(first, rest);
            if (macS2C != null)
            {
                byte[] macIn = ReadExact(32);
                byte[] seqb = { (byte)(seqS2C >> 24), (byte)(seqS2C >> 16), (byte)(seqS2C >> 8), (byte)seqS2C };
                byte[] expect = macS2C.ComputeHash(Concat(seqb, plain));
                for (int i = 0; i < 32; i++)
                {
                    if (macIn[i] != expect[i]) throw new Exception("SSH MAC 校验失败");
                }
            }
            seqS2C++;
            int pad = plain[4];
            int len = pktLen - pad - 1;
            if (pad < 4 || len < 0 || len > pktLen - 1) throw new Exception("SSH 填充长度非法");
            byte[] payload = new byte[len];
            Buffer.BlockCopy(plain, 5, payload, 0, len);
            return payload;
        }

        /// <summary>收包直到拿到期望类型；忽略 IGNORE/DEBUG，回应 GLOBAL_REQUEST。</summary>
        private byte[] ExpectPacket(byte want)
        {
            for (; ; )
            {
                byte[] p = RecvPacket();
                if (p.Length == 0) throw new Exception("SSH 空包");
                if (p[0] == want) return p;
                if (p[0] == MsgGlobalRequest)
                {
                    SendPacket(new byte[] { MsgRequestFailure });
                }
                else if (p[0] == MsgDisconnect)
                {
                    throw new Exception("服务端断开: " + ParseDisconnect(p));
                }
                else if (p[0] != MsgIgnore && p[0] != MsgDebug)
                {
                    throw new Exception("SSH 流程异常，期望消息 " + want + " 收到 " + p[0]);
                }
            }
        }

        private string ReadBannerLine()
        {
            var sb = new StringBuilder();
            for (int lines = 0; lines < 50; lines++)
            {
                sb.Length = 0;
                for (; ; )
                {
                    byte[] b = ReadExact(1);
                    if (b[0] == (byte)'\n') break;
                    if (b[0] != (byte)'\r') sb.Append((char)b[0]);
                    if (sb.Length > 4096) throw new Exception("SSH 横幅过长");
                }
                string line = sb.ToString();
                if (line.StartsWith("SSH-", StringComparison.Ordinal)) return line;
                // 服务端横幅前的自由文本行，跳过
            }
            throw new Exception("未收到 SSH 版本横幅");
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

        private static string ParseDisconnect(byte[] p)
        {
            try
            {
                var r = new SshReader(p, 1);
                uint code = r.R32();
                string msg = Encoding.UTF8.GetString(r.RString());
                return "code=" + code + " " + msg;
            }
            catch { return ""; }
        }

        // ===================== 加密算法 =====================

        private interface ISshCipher : IDisposable
        {
            int BlockSize { get; }
            void Transform(byte[] buf, int off, int len);
        }

        private static ISshCipher CreateCipher(string name, byte[] key, byte[] iv, bool encrypt)
        {
            if (name.EndsWith("-ctr", StringComparison.Ordinal)) return new AesCtr(key, iv);
            return new BlockCipher(name, key, iv, encrypt);
        }

        /// <summary>AES-CBC / 3DES-CBC；TransformBlock 保持跨包 CBC 链接状态。</summary>
        private sealed class BlockCipher : ISshCipher
        {
            private readonly SymmetricAlgorithm algorithm;
            private readonly ICryptoTransform transform;

            public int BlockSize { get; private set; }

            public BlockCipher(string name, byte[] key, byte[] iv, bool encrypt)
            {
                algorithm = name == "3des-cbc" ? (SymmetricAlgorithm)TripleDES.Create() : Aes.Create();
                algorithm.Mode = CipherMode.CBC;
                algorithm.Padding = PaddingMode.None;
                algorithm.Key = key;
                algorithm.IV = iv;
                BlockSize = algorithm.BlockSize / 8;
                transform = encrypt ? algorithm.CreateEncryptor() : algorithm.CreateDecryptor();
            }

            public void Transform(byte[] buf, int off, int len)
            {
                if (len == 0) return;
                if (len % BlockSize != 0) throw new Exception("SSH CBC 数据未按块对齐");
                transform.TransformBlock(buf, off, len, buf, off);
            }

            public void Dispose()
            {
                transform.Dispose();
                algorithm.Dispose();
            }
        }

        private sealed class AesCtr : ISshCipher
        {
            private readonly Aes aes;
            private readonly ICryptoTransform ecb;
            private readonly byte[] counter;
            private readonly byte[] stream = new byte[16];
            private int used = 16;

            public int BlockSize { get { return 16; } }

            public AesCtr(byte[] key, byte[] iv)
            {
                aes = Aes.Create();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                ecb = aes.CreateEncryptor();
                counter = (byte[])iv.Clone();
            }

            public void Transform(byte[] buf, int off, int len)
            {
                for (int i = 0; i < len; i++)
                {
                    if (used == 16) GenBlock();
                    buf[off + i] ^= stream[used++];
                }
            }

            private void GenBlock()
            {
                ecb.TransformBlock(counter, 0, 16, stream, 0);
                for (int i = 15; i >= 0; i--)
                {
                    if (++counter[i] != 0) break; // 大端进位
                }
                used = 0;
            }

            public void Dispose()
            {
                ecb.Dispose();
                aes.Dispose();
            }
        }

        // ===================== 二进制读写 =====================

        private sealed class SshWriter
        {
            private readonly MemoryStream ms = new MemoryStream();
            public void W8(int v) { ms.WriteByte((byte)v); }
            public void W32(long v)
            {
                ms.WriteByte((byte)(v >> 24)); ms.WriteByte((byte)(v >> 16));
                ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)v);
            }
            public void WBytes(byte[] b) { ms.Write(b, 0, b.Length); }
            public void WString(string s) { WString(Encoding.UTF8.GetBytes(s)); }
            public void WString(byte[] b) { W32(b.Length); WBytes(b); }
            /// <summary>mpint：去前导零，高位为 1 时补 0x00；零值编码为空。</summary>
            public void WMpInt(byte[] be)
            {
                if (be.Length == 0) { W32(0); return; }
                int start = 0;
                while (start < be.Length - 1 && be[start] == 0 && (be[start + 1] & 0x80) == 0) start++;
                if (be[start] == 0) { W32(0); return; } // 全零
                int n = be.Length - start;
                if ((be[start] & 0x80) != 0)
                {
                    W32(n + 1);
                    ms.WriteByte(0);
                    ms.Write(be, start, n);
                }
                else
                {
                    W32(n);
                    ms.Write(be, start, n);
                }
            }
            public void WMpInt(BigInteger v) { WMpInt(v.IsZero ? new byte[0] : v.ToByteArray(true, true)); }
            public byte[] Bytes() { return ms.ToArray(); }
        }

        private sealed class SshReader
        {
            private readonly byte[] d;
            private int pos;
            public SshReader(byte[] data, int offset) { d = data; pos = offset; }
            public int R8() { return d[pos++]; }
            public uint R32()
            {
                uint v = (uint)((d[pos] << 24) | (d[pos + 1] << 16) | (d[pos + 2] << 8) | d[pos + 3]);
                pos += 4;
                return v;
            }
            public byte[] RString()
            {
                int n = (int)R32();
                byte[] r = new byte[n];
                Buffer.BlockCopy(d, pos, r, 0, n);
                pos += n;
                return r;
            }
            public BigInteger RMpInt() { return new BigInteger(RString(), true, true); }
        }

        // ===================== 工具 =====================

        private static byte[] RandomBytes(int n)
        {
            byte[] b = new byte[n];
            RandomNumberGenerator.Fill(b);
            return b;
        }

        private static byte[] Slice(byte[] d, int off, int n)
        {
            byte[] r = new byte[n];
            Buffer.BlockCopy(d, off, r, 0, n);
            return r;
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

        private static byte[] FromHex(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++)
            {
                b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return b;
        }
    }
}
