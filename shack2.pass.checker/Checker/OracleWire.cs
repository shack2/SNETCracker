using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Oracle 最小客户端：仅实现弱口令检测所需的能力 ——
    /// TNS CONNECT/ACCEPT + TTI 协商 + O5Logon（11g，AES-192/SHA1）与 O3Logon（10g，AES-128/DES）认证，
    /// 以及 12.2+/21c 现代握手（跳过 SNS + 静态 TTC 能力包）+ 12C 认证（PBKDF2-HMAC-SHA512/AES-256）。
    /// 替代 Oracle.ManagedDataAccess.Core（约 5.6 MB IL，含完整类型系统/UDT/连接池等死代码）。
    /// 协议参考 nmap nselib/tns.lua（对 Oracle 10g/11g 实测可用的公开实现），
    /// 21c 流程取自 python-oracledb thin 模式实机抓包，常量见 OracleBlobs.g.cs / OracleBlobsModern.g.cs。
    /// 零第三方依赖、AOT 安全。
    /// 覆盖范围：10g/11g、默认允许 11g 认证的 12.1/18c/19c，以及强制新式协商的 12.2+/21c。
    /// </summary>
    internal sealed class OracleWire : IDisposable
    {
        private const byte TnsConnect = 1, TnsAccept = 2, TnsRefuse = 4, TnsData = 6, TnsResend = 11, TnsMarker = 12;
        private const int Version10g = 313, Version11g = 314;

        private Socket sock;
        private byte[] lastSent;

        /// <summary>排障开关：打开后向控制台输出各握手阶段。</summary>
        public static bool DebugLog = false;
        private static void Dbg(string stage) { if (DebugLog) Console.WriteLine("[OracleWire] " + stage); }

        /// <summary>服务端 TNS 协议版本（313≈10g，314≈11g+，318≈12.2+/21c）。</summary>
        public int ServerVersion;
        /// <summary>服务端操作系统标识（协议协商阶段取得）。</summary>
        public string ServerOs = "";
        /// <summary>true = 走了 12.2+/21c 现代握手流程（Connect 成功后确定，供上层缓存）。</summary>
        public bool IsModernFlow;
        /// <summary>现代流程认证成功后取得的服务端版本号（如 21.3.0.0）。</summary>
        public string ServerVersionNo = "";

        /// <summary>
        /// 建立连接并完成协议协商。modernHint：true 直接走现代流程；false 只走老流程；
        /// null 先老流程，老流程在协商阶段被服务端断开（21c+ 特征）时自动重连改走现代流程。
        /// </summary>
        public void Connect(string ip, int port, string serviceName, int timeoutSec, bool? modernHint = null)
        {
            if (modernHint == true)
            {
                ConnectModern(ip, port, serviceName, timeoutSec);
                return;
            }
            try
            {
                ConnectLegacy(ip, port, serviceName, timeoutSec);
            }
            catch (Exception ex) when (modernHint != false && IsDisconnect(ex))
            {
                // 21c+ 不再接受老式 SNS 协商，直接断开：重连走现代流程
                Dbg("老流程被断开（" + ex.GetType().Name + "），改走 12.2+ 现代流程");
                Dispose();
                sock = null;
                lastSent = null;
                ConnectModern(ip, port, serviceName, timeoutSec);
            }
        }

        private static bool IsDisconnect(Exception ex) => ex is EndOfStreamException || ex is SocketException;

        private void OpenSocket(string ip, int port, int timeoutSec)
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

        /// <summary>TNS CONNECT -> ACCEPT，取协议版本；12514 抛 OracleServiceUnknownException。</summary>
        private void TnsConnectAccept(byte[] connectPacket)
        {
            SendRaw(connectPacket);
            byte[] resp = RecvRaw();
            Dbg("CONNECT 响应类型=" + resp[1] + " 长度=" + resp.Length);
            byte type = resp[1];
            if (type == TnsRefuse)
            {
                string msg = Encoding.ASCII.GetString(resp, 2, resp.Length - 2);
                msg = msg.Trim('\0', ' ', '(', ')');
                if (msg.Contains("12514"))
                {
                    throw new OracleServiceUnknownException(msg);
                }
                throw new Exception("TNS 连接被拒绝: " + msg);
            }
            if (type != TnsAccept)
            {
                throw new Exception("TNS 握手失败，响应类型=" + type);
            }
            ServerVersion = resp.Length >= 4 ? (resp[2] << 8) | resp[3] : 0;
        }

        /// <summary>12.2+/21c 现代握手：74 字节扩展头 CONNECT（声明 319）+ 新式 DATA 包头 + 静态 TTC 能力包。</summary>
        private void ConnectModern(string ip, int port, string serviceName, int timeoutSec)
        {
            OpenSocket(ip, port, timeoutSec);
            TnsConnectAccept(BuildConnectPacketModern(ip, port, serviceName));

            // 新式协议协商：01 06 00 + 驱动名 + \0，响应同偏移含 OS 标识
            byte[] neg = ExchangeModern(Concat(new byte[] { 1, 6, 0 }, Encoding.ASCII.GetBytes("SNETCracker\0")));
            ServerOs = ParseModernOs(neg);
            Dbg("现代协议协商完成 OS=" + ServerOs);

            // 静态 TTC 能力协商包（python-oracledb thin 对 21c 抓包，与驱动/平台无关）
            SendDataModern(TtcPayload());
            RecvRaw();
            IsModernFlow = true;
            Dbg("TTC 能力协商完成（现代流程）");
        }

        /// <summary>现代流程 DATA 包负载含 2 字节标志位，抓包常量前 10 字节（8 头 + 2 标志）剥掉。</summary>
        private static byte[] ttcPayload;
        private static byte[] TtcPayload()
        {
            if (ttcPayload == null)
            {
                byte[] full = FromHex(OracleBlobsModern.Ttc);
                ttcPayload = new byte[full.Length - 10];
                Buffer.BlockCopy(full, 10, ttcPayload, 0, ttcPayload.Length);
            }
            return ttcPayload;
        }

        /// <summary>从现代协议协商响应中取 OS 标识：找 01 06 00 后的 C 字符串。</summary>
        private static string ParseModernOs(byte[] resp)
        {
            int limit = Math.Min(resp.Length - 3, 12);
            for (int i = 2; i < limit; i++)
            {
                if (resp[i] == 1 && resp[i + 1] == 6 && resp[i + 2] == 0)
                {
                    int z = i + 3, end = z;
                    while (end < resp.Length && resp[end] != 0) end++;
                    return Encoding.ASCII.GetString(resp, z, end - z);
                }
            }
            return "";
        }

        /// <summary>10g/11g 老式握手：SNS + 旧式协议协商 + TTI 协商。</summary>
        private void ConnectLegacy(string ip, int port, string serviceName, int timeoutSec)
        {
            OpenSocket(ip, port, timeoutSec);
            TnsConnectAccept(BuildConnectPacket(ip, port, serviceName));

            // 2) SNS（安全协商，固定负载）
            Exchange(FromHex(OracleBlobs.Sns));
            Dbg("SNS 完成");

            // 3) 协议协商 -> 取服务端 OS 标识
            byte[] neg = Exchange(Concat(FromHex("0106050403020100"), Encoding.ASCII.GetBytes("Linuxi386/Linux-2.0.34-8.1.0\0")));
            Dbg("协议协商响应长度=" + neg.Length);
            // flags(2) + neg(1)==1 + ver(1)==6 + skip(1) + cstring(os)
            if (neg.Length < 6 || neg[2] != 1)
            {
                throw new Exception("TNS 协议协商失败");
            }
            int z = 5;
            while (z < neg.Length && neg[z] != 0) z++;
            ServerOs = Encoding.ASCII.GetString(neg, 5, z - 5);

            // 4) TTI 协商（按服务端 OS 选择负载与应答次数）
            bool legacy = ServerOs == "Linuxi386/Linux-2.0.34-8.1.0" || ServerOs == "IBMPC/WIN_NT-8.1.0";
            if (legacy)
            {
                Exchange(FromHex(OracleBlobs.Unknown1_Legacy));
            }
            else
            {
                // nmap tns.lua：WIN_NT 系列（含 64 位）用 Win blob，x86_64 Linux 用 X64 blob，其他按 X64 兜底
                bool win = ServerOs.StartsWith("IBMPC/WIN_NT", StringComparison.Ordinal);
                SendData(FromHex(win ? OracleBlobs.Unknown1_Win : OracleBlobs.Unknown1_X64));
                SendData(FromHex(win ? OracleBlobs.Unknown2_Win : OracleBlobs.Unknown2_X64));
                RecvRaw();
                if (ServerVersion == Version10g && ServerOs.StartsWith("IBMPC/WIN_NT", StringComparison.Ordinal))
                {
                    RecvRaw(); // 10g Windows 多一个应答包
                }
            }
            Dbg("TTI 协商完成 OS=" + ServerOs + " ver=" + ServerVersion);
        }

        /// <summary>认证；口令错误返回 false（error 为 ORA 错误），网络/协议异常直接抛出。按握手流程自动选 10g/11g 或 12c+。</summary>
        public bool Login(string user, string password, out string error)
        {
            return IsModernFlow ? Login12c(user, password, out error) : LoginLegacy(user, password, out error);
        }

        /// <summary>O5Logon/O3Logon 认证（10g/11g 及兼容模式的 12.1/18c/19c）。</summary>
        private bool LoginLegacy(string user, string password, out string error)
        {
            error = null;
            bool legacy = ServerOs == "Linuxi386/Linux-2.0.34-8.1.0" || ServerOs == "IBMPC/WIN_NT-8.1.0";

            // 1) PreAuth：发用户名，取服务端会话密钥与盐
            byte[] preUnknown = legacy
                ? InsertUserLen(FromHex("0238be080800000001000000a851bfbf05000000504ebfbf7853bfbf"), 5, user)
                : FromHex("0201040000000100000001050000000101");
            byte[] payload = Concat(
                new byte[] { 0, 0, 0x03, 0x76 },
                preUnknown,
                PackS1(user),
                MarshalKvp("AUTH_TERMINAL", "pts/1", 0),
                MarshalKvp("AUTH_PROGRAM_NM", "sqlplus@client (TNS V1-V3)", 0),
                MarshalKvp("AUTH_MACHINE", "client", 0),
                MarshalKvp("AUTH_PID", "1000", 0),
                MarshalKvp("AUTH_SID", "client", 0));

            Dictionary<string, string> pre;
            try
            {
                pre = ParseKvps(Exchange(payload));
            }
            catch (OracleAuthException)
            {
                throw; // PreAuth 阶段被 MARKER 拒绝属协议异常
            }

            if (!pre.TryGetValue("AUTH_SESSKEY", out string srvSessKeyHex) || srvSessKeyHex.Length == 0)
            {
                throw new Exception("服务端未返回 AUTH_SESSKEY");
            }
            pre.TryGetValue("AUTH_VFR_DATA", out string saltHex);
            byte[] srvSessKeyEnc = FromHex(srvSessKeyHex);

            // 2) 计算客户端会话密钥与加密口令
            string cliSessKeyHex, authPassHex;
            if (ServerVersion == Version11g && saltHex != null && saltHex.Length > 2)
            {
                (cliSessKeyHex, authPassHex) = Encrypt11g(password, srvSessKeyEnc, FromHex(saltHex));
            }
            else
            {
                (cliSessKeyHex, authPassHex) = Encrypt10g(user, password, srvSessKeyEnc);
            }

            // 3) Auth：回送客户端会话密钥 + 加密口令
            byte[] authUnknown = legacy
                ? InsertUserLen(FromHex("0338be080800000001010000cc7dbfbf0d000000747abfbf608abfbf"), 5, user)
                : FromHex("03010400000001010000010d0000000101");
            byte[] authPayload = Concat(
                new byte[] { 0, 0, 0x03, 0x73 },
                authUnknown,
                PackS1(user),
                MarshalKvp("AUTH_SESSKEY", cliSessKeyHex, 1),
                MarshalKvp("AUTH_PASSWORD", authPassHex, 0),
                MarshalKvp("AUTH_RTT", "25456", 0),
                MarshalKvp("AUTH_CLNT_MEM", "4096", 0),
                MarshalKvp("AUTH_TERMINAL", "pts/1", 0),
                MarshalKvp("AUTH_PROGRAM_NM", "sqlplus@client (TNS V1-V3)", 0),
                MarshalKvp("AUTH_MACHINE", "client", 0),
                MarshalKvp("AUTH_PID", "1000", 0),
                MarshalKvp("AUTH_SID", "client", 0),
                MarshalKvp("AUTH_ACL", "4400", 0),
                MarshalKvp("AUTH_ALTER_SESSION", "ALTER SESSION SET TIME_ZONE='+02:00'\0", 0),
                MarshalKvp("AUTH_LOGICAL_SESSION_ID", ToHex(RandomBytes(16)), 0),
                MarshalKvp("AUTH_FAILOVER_ID", "", 0));

            byte[] authResp;
            try
            {
                authResp = Exchange(authPayload);
            }
            catch (OracleAuthException oe)
            {
                error = oe.Message;
                return false; // ORA-01017 等认证类错误
            }

            Dictionary<string, string> kvps = ParseKvps(authResp);
            if (kvps.TryGetValue("AUTH_SESSION_ID", out string sid) && !string.IsNullOrEmpty(sid))
            {
                return true;
            }
            error = "认证响应缺少 AUTH_SESSION_ID";
            return false;
        }

        /// <summary>
        /// 12C 认证（12.2+/21c 现代流程）：PBKDF2-HMAC-SHA512 派生口令密钥，
        /// AES-256 解密服务端会话密钥，组合密钥加密口令与会话材料。
        /// 消息格式与 python-oracledb 2.5.1 thin 模式逐字节对齐（已实机验证）。
        /// </summary>
        private bool Login12c(string user, string password, out string error)
        {
            error = null;
            byte[] ub = Encoding.UTF8.GetBytes(user);

            // 1) PreAuth：发用户名，取会话密钥、盐与 PBKDF2 参数
            byte[] payload = Concat(
                AuthPrefix(0x76, 1, ub.Length, 1, 5),
                PackS1(user),
                MarshalKvpModern("AUTH_TERMINAL", "unknown", 0),
                MarshalKvpModern("AUTH_PROGRAM_NM", "SNETCracker", 0),
                MarshalKvpModern("AUTH_MACHINE", "client", 0),
                MarshalKvpModern("AUTH_PID", "1000", 0),
                MarshalKvpModern("AUTH_SID", "client", 0));

            byte[] preResp;
            try
            {
                preResp = ExchangeModern(payload);
            }
            catch (OracleAuthException)
            {
                throw; // PreAuth 阶段被 MARKER 拒绝属协议异常
            }

            string srvSessKeyHex = FindKvpModern(preResp, "AUTH_SESSKEY");
            string vfrDataHex = FindKvpModern(preResp, "AUTH_VFR_DATA");
            string cskSaltHex = FindKvpModern(preResp, "AUTH_PBKDF2_CSK_SALT");
            string vgenStr = FindKvpModern(preResp, "AUTH_PBKDF2_VGEN_COUNT");
            string sderStr = FindKvpModern(preResp, "AUTH_PBKDF2_SDER_COUNT");
            if (string.IsNullOrEmpty(srvSessKeyHex))
            {
                throw new Exception("服务端未返回 AUTH_SESSKEY");
            }
            if (string.IsNullOrEmpty(vfrDataHex) || string.IsNullOrEmpty(cskSaltHex))
            {
                throw new Exception("服务端未返回 12C 认证盐（AUTH_VFR_DATA/CSK_SALT）");
            }
            int vgen = int.TryParse(vgenStr, out int v) ? v : 4096;
            int sder = int.TryParse(sderStr, out int s) ? s : 3;

            // 2) 计算客户端会话密钥、speedy key 与加密口令
            (string cliSessKeyHex, string speedyKeyHex, string authPassHex) = Encrypt12c(
                password, FromHex(srvSessKeyHex), FromHex(vfrDataHex), FromHex(cskSaltHex), vgen, sder);

            // 3) Auth：回送会话密钥 + speedy key + 加密口令（flags：SESSKEY=1、ALTER=1、其余 0）
            byte[] authPayload = Concat(
                AuthPrefix(0x73, 2, ub.Length, 0x101, 7),
                PackS1(user),
                MarshalKvpModern("AUTH_SESSKEY", cliSessKeyHex, 1),
                MarshalKvpModern("AUTH_PBKDF2_SPEEDY_KEY", speedyKeyHex, 0),
                MarshalKvpModern("AUTH_PASSWORD", authPassHex, 0),
                MarshalKvpModern("SESSION_CLIENT_CHARSET", "873", 0),
                MarshalKvpModern("SESSION_CLIENT_DRIVER_NAME", "SNETCracker thn : 1.0", 0),
                MarshalKvpModern("SESSION_CLIENT_VERSION", "318000000", 0),
                MarshalKvpModern("AUTH_ALTER_SESSION", "ALTER SESSION SET TIME_ZONE='+08:00'\0", 1));

            byte[] authResp;
            try
            {
                authResp = ExchangeModern(authPayload);
            }
            catch (OracleAuthException oe)
            {
                error = oe.Message;
                return false; // ORA-01017 等认证类错误
            }

            string sid = FindKvpModern(authResp, "AUTH_SESSION_ID");
            if (!string.IsNullOrEmpty(sid))
            {
                string verNo = FindKvpModern(authResp, "AUTH_VERSION_NO");
                if (long.TryParse(verNo, out long vn))
                {
                    ServerVersionNo = ((vn >> 24) & 0xFF) + "." + ((vn >> 16) & 0xFF) + "." +
                                      ((vn >> 8) & 0xFF) + "." + (vn & 0xFF);
                }
                return true;
            }
            error = "认证响应缺少 AUTH_SESSION_ID";
            return false;
        }

        /// <summary>
        /// Auth 消息前缀：消息类型(3) + 功能码 + 序号 + has_user(1) + ub4(用户名长) +
        /// ub4(auth_mode) + 指针(1) + ub4(KVP 对数) + 指针(1) + 指针(1)。
        /// </summary>
        private static byte[] AuthPrefix(byte func, byte seq, int userLen, int authMode, int numPairs)
        {
            return Concat(
                new byte[] { 3, func, seq, 1 },
                Ub4(userLen),
                Ub4(authMode),
                new byte[] { 1 },
                Ub4(numPairs),
                new byte[] { 1, 1 });
        }

        /// <summary>通用格式 32 位整数：0→00；≤255→01 xx；≤65535→02 xxxx；否则 04 xxxxxxxx。</summary>
        private static byte[] Ub4(long value)
        {
            if (value == 0)
            {
                return new byte[] { 0 };
            }
            if (value <= 0xFF)
            {
                return new byte[] { 1, (byte)value };
            }
            if (value <= 0xFFFF)
            {
                return new byte[] { 2, (byte)(value >> 8), (byte)value };
            }
            return new byte[] { 4, (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value };
        }

        /// <summary>12C 认证加密：返回 (客户端会话密钥 hex, speedy key hex, 加密口令 hex)。</summary>
        private static (string, string, string) Encrypt12c(
            string pass, byte[] sessKeyEnc, byte[] verifierData, byte[] cskSalt, int vgenCount, int sderCount)
        {
            byte[] pwdBytes = Encoding.UTF8.GetBytes(pass);

            // 口令密钥：PBKDF2-HMAC-SHA512(口令, 盐+固定串, VGEN_COUNT, 64)
            byte[] passwordKey = Pbkdf2Sha512(pwdBytes,
                Concat(verifierData, Encoding.ASCII.GetBytes("AUTH_PBKDF2_SPEEDY_KEY")), vgenCount, 64);
            // AES-256 密钥：SHA512(口令密钥+盐) 前 32 字节
            byte[] passwordHash = SHA512.HashData(Concat(passwordKey, verifierData));
            Array.Resize(ref passwordHash, 32);

            byte[] partA = AesCrypt(sessKeyEnc, passwordHash, false, PaddingMode.None);
            byte[] partB = RandomBytes(32);
            byte[] encClientKey = AesCrypt(partB, passwordHash, true, PaddingMode.None);

            // 组合密钥：PBKDF2(大写 hex(partB+partA) 的 ASCII, CSK_SALT, SDER_COUNT, 32)
            byte[] tempHex = Encoding.ASCII.GetBytes(ToHex(Concat(partB, partA)));
            byte[] comboKey = Pbkdf2Sha512(tempHex, cskSalt, sderCount, 32);

            byte[] speedy = AesCrypt(Concat(RandomBytes(16), passwordKey), comboKey, true, PaddingMode.PKCS7);
            string speedyHex = ToHex(speedy);
            if (speedyHex.Length > 160)
            {
                speedyHex = speedyHex.Substring(0, 160);
            }
            byte[] authPass = AesCrypt(Concat(RandomBytes(16), pwdBytes), comboKey, true, PaddingMode.PKCS7);
            return (ToHex(encClientKey), speedyHex, ToHex(authPass));
        }

        private static byte[] Pbkdf2Sha512(byte[] password, byte[] salt, int iterations, int bytes)
        {
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, bytes);
        }

        /// <summary>取服务端标识用于 Banner 展示。</summary>
        public string Banner()
        {
            if (IsModernFlow)
            {
                string ver = ServerVersionNo.Length > 0 ? ServerVersionNo : "12.2+";
                return "Oracle " + ver + (ServerOs.Length > 0 ? " (" + ServerOs + ")" : "");
            }
            string v = ServerVersion == Version11g ? "11g+" : ServerVersion == Version10g ? "10g" : "v" + ServerVersion;
            return "Oracle " + v + (ServerOs.Length > 0 ? " (" + ServerOs + ")" : "");
        }

        public void Dispose()
        {
            try
            {
                if (sock != null && sock.Connected)
                {
                    SendData(new byte[] { 0x00, 0x40 }); // EOF
                }
            }
            catch { }
            try { sock?.Close(); } catch { }
        }

        // ===================== 认证加密 =====================

        /// <summary>11g O5Logon：SHA1(pass+salt) 作 AES-192 密钥解密服务端会话密钥，组合密钥加密口令。</summary>
        private static (string, string) Encrypt11g(string pass, byte[] srvSessKeyEnc, byte[] salt)
        {
            byte[] pwHash = SHA1.HashData(Concat(Encoding.UTF8.GetBytes(pass), salt));
            Array.Resize(ref pwHash, 24); // 补 4 个 0 凑 AES-192

            byte[] srvSessKey = AesCrypt(srvSessKeyEnc, pwHash, false, PaddingMode.None);
            byte[] cliSessKey = Concat(RandomBytes(40), new byte[] { 8, 8, 8, 8, 8, 8, 8, 8 });

            byte[] combined = new byte[24];
            for (int i = 0; i < 24; i++)
            {
                combined[i] = (byte)(srvSessKey[16 + i] ^ cliSessKey[16 + i]);
            }
            byte[] key24 = Concat(MD5.HashData(combined.AsSpan(0, 16).ToArray()), MD5.HashData(combined.AsSpan(16, 8).ToArray()));
            Array.Resize(ref key24, 24);

            byte[] cliSessKeyEnc = AesCrypt(cliSessKey, pwHash, true, PaddingMode.None);
            byte[] authPass = AesCrypt(Concat(RandomBytes(16), Encoding.UTF8.GetBytes(pass)), key24, true, PaddingMode.PKCS7);
            return (ToHex(cliSessKeyEnc), ToHex(authPass));
        }

        /// <summary>10g O3Logon：DES 口令哈希作 AES-128 密钥。</summary>
        private static (string, string) Encrypt10g(string user, string pass, byte[] srvSessKeyEnc)
        {
            byte[] pwHash = Concat(HashPassword10g(user, pass), new byte[8]); // 8 字节哈希补 0 凑 AES-128

            byte[] srvSessKey = AesCrypt(srvSessKeyEnc, pwHash, false, PaddingMode.None);
            byte[] cliSessKey = FromHex("FAF5034314546426F329B1DAB1CDC5B8FF94349E0875623160350B0E13A0DA36");
            byte[] rnd = FromHex("4C31AFE05F3B012C0AE9AB0CDFF0C508");

            byte[] combined = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                combined[i] = (byte)(srvSessKey[16 + i] ^ cliSessKey[16 + i]);
            }
            byte[] key16 = MD5.HashData(combined);

            byte[] cliSessKeyEnc = AesCrypt(cliSessKey, pwHash, true, PaddingMode.None);
            byte[] authPass = AesCrypt(Concat(rnd, Encoding.UTF8.GetBytes(pass)), key16, true, PaddingMode.PKCS7);
            return (ToHex(cliSessKeyEnc), ToHex(authPass));
        }

        /// <summary>Oracle 10g 口令哈希：UTF-16BE(大写 user+pass) 经两轮 DES-CBC 取末块。</summary>
        private static byte[] HashPassword10g(string user, string pass)
        {
            string up = (user + pass).ToUpperInvariant();
            byte[] data = Encoding.BigEndianUnicode.GetBytes(up);
            int pad = (8 - data.Length % 8) % 8;
            if (pad > 0) Array.Resize(ref data, data.Length + pad);

            byte[] iv2 = DesCbc(data, FromHex("0123456789ABCDEF"));
            return DesCbc(data, iv2);
        }

        private static byte[] DesCbc(byte[] data, byte[] key)
        {
            using (DES des = DES.Create())
            {
                des.Key = key;
                des.IV = new byte[8];
                des.Padding = PaddingMode.None;
                byte[] enc = des.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
                byte[] last = new byte[8];
                Buffer.BlockCopy(enc, enc.Length - 8, last, 0, 8);
                return last;
            }
        }

        private static byte[] AesCrypt(byte[] data, byte[] key, bool encrypt, PaddingMode padding)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = new byte[16];
                aes.Mode = CipherMode.CBC;
                aes.Padding = padding;
                return encrypt
                    ? aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length)
                    : aes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);
            }
        }

        // ===================== TNS 包收发 =====================

        /// <summary>发送 DATA 负载并接收响应；MARKER 自动应答并解析 ORA 错误（抛 OracleAuthException）。</summary>
        private byte[] Exchange(byte[] dataPayload)
        {
            SendData(dataPayload);
            byte[] resp = RecvRaw();
            if (resp[1] == TnsMarker)
            {
                throw new OracleAuthException(HandleMarker());
            }
            if (resp[1] != TnsData)
            {
                throw new Exception("TNS 响应类型异常: " + resp[1]);
            }
            return resp;
        }

        /// <summary>现代流程（12.2+/21c）：DATA 包用新式包头（长度在 2-3 字节），负载前带 2 字节标志位。</summary>
        private void SendDataModern(byte[] payload) => SendRaw(BuildPacketModern(TnsData, Concat(new byte[] { 0, 0 }, payload)));

        /// <summary>现代流程的 Exchange：语义同 Exchange，仅发送侧带标志位。</summary>
        private byte[] ExchangeModern(byte[] payload)
        {
            SendDataModern(payload);
            byte[] resp = RecvRaw();
            if (resp[1] == TnsMarker)
            {
                throw new OracleAuthException(HandleMarker());
            }
            if (resp[1] != TnsData)
            {
                throw new Exception("TNS 响应类型异常: " + resp[1]);
            }
            return resp;
        }

        /// <summary>MARKER 流程：再收一个 MARKER，回 Attention，收 DATA 取 ORA 错误文本。</summary>
        private string HandleMarker()
        {
            byte[] m2 = RecvRaw();
            if (m2[1] != TnsMarker)
            {
                throw new Exception("MARKER 流程异常");
            }
            // 现代会话（12.2+）所有包都用新式包头，Attention 也不例外
            SendRaw(IsModernFlow
                ? BuildPacketModern(TnsMarker, new byte[] { 1, 0, 2 })
                : BuildPacket(TnsMarker, new byte[] { 1, 0, 2 })); // Attention
            byte[] errPkt = RecvRaw();
            byte[] d = errPkt; // 含 8 字节头
            int body = 8;
            bool b1 = d.Length > body + 9 && d[body + 9] == 1;
            int pos = body + (b1 ? 98 : 68);
            if (pos >= d.Length)
            {
                return "ORA-UNKNOWN";
            }
            int len = d[pos];
            return Encoding.ASCII.GetString(d, pos + 1, Math.Min(len, d.Length - pos - 1)).TrimEnd('\0');
        }

        private void SendData(byte[] payload) => SendRaw(BuildPacket(TnsData, payload));

        private void SendRaw(byte[] packet)
        {
            lastSent = packet;
            sock.Send(packet);
        }

        /// <summary>收一个 TNS 包（自动处理 RESEND）；返回「类型字节+负载」视图：ret[0]=长度无关，ret[1]=类型。</summary>
        private byte[] RecvRaw()
        {
            for (int retry = 0; ; retry++)
            {
                byte[] hdr = ReadExact(8);
                int len = (hdr[0] << 8) | hdr[1];
                if (len == 0)
                {
                    len = (hdr[2] << 8) | hdr[3]; // 12.2+ 新式会话 DATA 包头：长度在 2-3 字节
                }
                if (len < 8 || len > 1024 * 1024)
                {
                    throw new Exception("TNS 包长度非法: " + len);
                }
                byte[] body = ReadExact(len - 8);
                byte type = hdr[4];
                if (type == TnsResend && retry < 5 && lastSent != null)
                {
                    SendRaw(lastSent);
                    continue;
                }
                // 返回 type(1) + body，便于统一用 resp[1] 判类型
                byte[] ret = new byte[body.Length + 2];
                ret[1] = type;
                Buffer.BlockCopy(body, 0, ret, 2, body.Length);
                return ret;
            }
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

        private static byte[] BuildPacket(byte type, byte[] payload)
        {
            byte[] pkt = new byte[payload.Length + 8];
            int len = pkt.Length;
            pkt[0] = (byte)(len >> 8); pkt[1] = (byte)len;
            pkt[4] = type;
            Buffer.BlockCopy(payload, 0, pkt, 8, payload.Length);
            return pkt;
        }

        /// <summary>新式包头（12.2+ 现代会话 DATA 包）：前两字节为 0，长度在 2-3 字节。</summary>
        private static byte[] BuildPacketModern(byte type, byte[] payload)
        {
            byte[] pkt = new byte[payload.Length + 8];
            int len = pkt.Length;
            pkt[2] = (byte)(len >> 8); pkt[3] = (byte)len;
            pkt[4] = type;
            Buffer.BlockCopy(payload, 0, pkt, 8, payload.Length);
            return pkt;
        }

        /// <summary>12.2+/21c CONNECT 包：74 字节扩展头（声明 version=319）+ 内联连接串，连接串从偏移 74 开始。</summary>
        private static byte[] BuildConnectPacketModern(string host, int port, string serviceName)
        {
            string connData = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=" + host + ")(PORT=" + port + "))" +
                              "(CONNECT_DATA=(SERVER=DEDICATED)(SERVICE_NAME=" + serviceName + ")" +
                              "(CID=(PROGRAM=SNETCracker)(HOST=" + host + ")(USER=client))))";
            byte[] cd = Encoding.ASCII.GetBytes(connData);
            byte[] hdr = FromHex(OracleBlobsModern.ConnectHeader74);
            int total = hdr.Length + cd.Length;
            hdr[0] = (byte)(total >> 8); hdr[1] = (byte)total;   // 包总长
            hdr[24] = (byte)(cd.Length >> 8); hdr[25] = (byte)cd.Length; // 连接串长
            return Concat(hdr, cd);
        }

        private static byte[] BuildConnectPacket(string host, int port, string serviceName)
        {
            string connData = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=" + host + ")(PORT=" + port + "))" +
                              "(CONNECT_DATA=(SERVER=DEDICATED)(SERVICE_NAME=" + serviceName + ")" +
                              "(CID=(PROGRAM=sqlplus)(HOST=" + host + ")(USER=client))))";
            byte[] cd = Encoding.ASCII.GetBytes(connData);

            // 8 字节 TNS 公共头 + 50 字节 CONNECT 头，connect data 从偏移 58 开始
            var ms = new MemoryStream();
            void W2(int v) { ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)v); }
            void W4(int v) { for (int i = 3; i >= 0; i--) ms.WriteByte((byte)(v >> (8 * i))); }
            W2(58 + cd.Length); W2(0);     // 包总长 + 校验和
            ms.WriteByte(TnsConnect); ms.WriteByte(0); // 类型=CONNECT + 保留
            W2(0);                         // 头校验和
            W2(314); W2(300); W2(0x0c41); W2(8192); W2(32767); W2(0x7f08); W2(0); W2(0x0100);
            W2(cd.Length); W2(58);
            W4(512);               // max connect data
            ms.WriteByte(0x41); ms.WriteByte(0x41); // flags
            W4(0); W4(0);          // trace cross
            W4(0); W4(0); W4(0); W4(0); // trace unique conn + 保留（16 字节）
            ms.Write(cd, 0, cd.Length);
            return ms.ToArray();
        }

        // ===================== KVP 编解码 =====================

        /// <summary>现代流程（12.2+）KVP 编码：key/value = 01 len len data（空值为 00），flags = 长度前缀大端整数。</summary>
        private static byte[] MarshalKvpModern(string key, string value, int flags)
        {
            byte[] kb = Encoding.ASCII.GetBytes(key);
            byte[] vb = Encoding.ASCII.GetBytes(value);
            if (kb.Length > 255 || vb.Length > 255)
            {
                throw new Exception("KVP 超长: " + key);
            }
            var ms = new MemoryStream();
            ms.WriteByte(1); ms.WriteByte((byte)kb.Length); ms.WriteByte((byte)kb.Length);
            ms.Write(kb, 0, kb.Length);
            if (vb.Length == 0)
            {
                ms.WriteByte(0);
            }
            else
            {
                ms.WriteByte(1); ms.WriteByte((byte)vb.Length); ms.WriteByte((byte)vb.Length);
                ms.Write(vb, 0, vb.Length);
            }
            if (flags == 0)
            {
                ms.WriteByte(0);
            }
            else
            {
                // 长度前缀大端整数：1 -> 01 01，0x4815 -> 02 48 15
                var tmp = new List<byte>();
                for (int f = flags; f > 0; f >>= 8) tmp.Insert(0, (byte)f);
                ms.WriteByte((byte)tmp.Count);
                foreach (byte b in tmp) ms.WriteByte(b);
            }
            return ms.ToArray();
        }

        /// <summary>
        /// 现代流程响应的容错 KVP 查找：按 01 len len + key 模式全文扫描，取紧随其后的值。
        /// （响应尾部有未识别结构，严格顺序解析不可靠；键名/值均为 ASCII 与 hex，误匹配概率可忽略。）
        /// </summary>
        private static string FindKvpModern(byte[] resp, string key)
        {
            byte[] kb = Encoding.ASCII.GetBytes(key);
            for (int i = 2; i + kb.Length + 3 <= resp.Length; i++)
            {
                if (resp[i] != 1 || resp[i + 1] != kb.Length || resp[i + 2] != kb.Length)
                {
                    continue;
                }
                bool match = true;
                for (int j = 0; j < kb.Length; j++)
                {
                    if (resp[i + 3 + j] != kb[j]) { match = false; break; }
                }
                if (!match)
                {
                    continue;
                }
                int p = i + 3 + kb.Length;
                if (p >= resp.Length || resp[p] == 0)
                {
                    return ""; // 空值
                }
                if (resp[p] == 1 && p + 3 < resp.Length && resp[p + 1] == resp[p + 2])
                {
                    int vl = resp[p + 1];
                    if (p + 3 + vl <= resp.Length)
                    {
                        return Encoding.ASCII.GetString(resp, p + 3, vl);
                    }
                }
                return null; // 键找到但值格式异常
            }
            return null;
        }

        private static byte[] MarshalKvp(string key, string value, int flags)
        {
            byte[] kb = MarshalComponent(Encoding.ASCII.GetBytes(key));
            byte[] vb = MarshalComponent(Encoding.ASCII.GetBytes(value));
            byte[] fb = BitConverter.GetBytes(flags); // 小端
            return Concat(kb, vb, fb);
        }

        private static byte[] MarshalComponent(byte[] v)
        {
            var ms = new MemoryStream();
            void W4le(int n) { for (int i = 0; i < 4; i++) ms.WriteByte((byte)(n >> (8 * i))); }
            W4le(v.Length);
            if (v.Length == 0) return ms.ToArray();
            const int maxChunk = 64;
            if (v.Length > maxChunk)
            {
                ms.WriteByte(0xFE);
                for (int pos = 0; pos < v.Length; pos += maxChunk)
                {
                    int n = Math.Min(maxChunk, v.Length - pos);
                    ms.WriteByte((byte)n);
                    ms.Write(v, pos, n);
                }
                ms.WriteByte(0);
            }
            else
            {
                ms.WriteByte((byte)v.Length);
                ms.Write(v, 0, v.Length);
            }
            return ms.ToArray();
        }

        /// <summary>解析 DATA 响应中的 KVP：ret[0..1]=flags，ret[3]=数量，ret[5] 起为 KVP 序列。</summary>
        private static Dictionary<string, string> ParseKvps(byte[] resp)
        {
            // resp 布局：ret[0] 保留, ret[1]=类型, ret[2..]=DATA 负载(flags 2 字节起)
            byte[] d = resp;
            int baseIdx = 2; // 跳过类型视图头
            var map = new Dictionary<string, string>(StringComparer.Ordinal);
            if (d.Length < baseIdx + 6) return map;
            int count = d[baseIdx + 3];
            int pos = baseIdx + 5;
            for (int i = 0; i < count && pos < d.Length; i++)
            {
                string key = UnmarshalComponent(d, ref pos);
                string val = UnmarshalComponent(d, ref pos);
                pos += 4; // flags
                if (key.Length > 0) map[key] = val;
            }
            return map;
        }

        private static string UnmarshalComponent(byte[] d, ref int pos)
        {
            int total = d[pos] | (d[pos + 1] << 8) | (d[pos + 2] << 16) | (d[pos + 3] << 24);
            pos += 4;
            if (total == 0) return "";
            var ms = new MemoryStream();
            bool chunked = d[pos] == 0xFE;
            if (chunked) pos++;
            while (true)
            {
                int n = d[pos++];
                if (n == 0 && chunked) break;
                ms.Write(d, pos, n);
                pos += n;
                if (!chunked) break;
            }
            return Encoding.ASCII.GetString(ms.ToArray());
        }

        // ===================== 工具 =====================

        private sealed class OracleAuthException : Exception
        {
            public OracleAuthException(string msg) : base(msg) { }
        }

        /// <summary>TNS-12514：监听器不认识请求的服务名，供上层换候选服务名重试。</summary>
        public sealed class OracleServiceUnknownException : Exception
        {
            public OracleServiceUnknownException(string msg) : base(msg) { }
        }

        private static byte[] InsertUserLen(byte[] blob, int at, string user)
        {
            // legacy 变体需在固定偏移写入用户名长度
            blob[at] = (byte)Encoding.ASCII.GetByteCount(user);
            return blob;
        }

        private static byte[] PackS1(string s)
        {
            byte[] b = Encoding.ASCII.GetBytes(s);
            byte[] r = new byte[b.Length + 1];
            r[0] = (byte)b.Length;
            Buffer.BlockCopy(b, 0, r, 1, b.Length);
            return r;
        }

        private static byte[] RandomBytes(int n)
        {
            byte[] b = new byte[n];
            RandomNumberGenerator.Fill(b);
            return b;
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

        private static string ToHex(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data) sb.Append(b.ToString("X2"));
            return sb.ToString();
        }
    }
}
