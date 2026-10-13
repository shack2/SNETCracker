using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// SQL Server 最小客户端：仅实现弱口令检测所需的能力 ——
    /// TDS Pre-Login + Login7（SQL 身份验证，密码为 nibble 交换 XOR 0xA5 混淆）。
    /// 替代 Microsoft.Data.SqlClient（约 0.6 MB IL + 0.57 MB 原生 SNI.dll）。
    /// 协议参考 MS-TDS 开放规范。零第三方依赖、AOT 安全。覆盖：SQL Server 2005+（TDS 7.x）。
    /// 支持强制加密实例（Pre-Login 协商 ENCRYPTION=REQ 时在 Login7 前升级为 TLS 通道，不校验证书链）；
    /// 不支持：Windows 集成认证（NTLM/SSPI）。
    /// </summary>
    internal sealed class TdsWire : IDisposable
    {
        private const byte PktPreLogin = 0x12, PktLogin7 = 0x10, PktResponse = 0x04;
        private const byte TokLoginAck = 0xAD, TokError = 0xAA, TokInfo = 0xAB, TokEnvChange = 0xE3;
        private const byte TokDone = 0xFD, TokDoneProc = 0xFE, TokDoneInProc = 0xFF;

        private Socket sock;
        private Stream stream; // 强制加密时非空：Pre-Login 后升级为 TLS，Login7 走加密通道
        private string host;   // TLS SNI / 重连用
        private int portNum;
        private int timeoutSecF;

        /// <summary>服务端版本（LoginAck 提取，如 16.0.1000）。</summary>
        public string ServerVersion = "";

        public void Connect(string ip, int port, int timeoutSec)
        {
            host = ip;
            portNum = port;
            timeoutSecF = timeoutSec;
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

        /// <summary>强制加密重试前的重连：关闭旧连接，按原参数新建 TCP。</summary>
        private void Reconnect()
        {
            try { stream?.Close(); } catch { }
            stream = null;
            try { sock?.Close(); } catch { }
            Connect(host, portNum, timeoutSecF);
        }

        /// <summary>认证；口令错误(18456)返回 false，网络/协议异常直接抛出。
        /// 默认走 NOT_SUP 明文路径（已验证兼容各版本实例）；仅当服务端 REQ 强制加密时，重连并升级 TLS 重试一次。</summary>
        public bool Login(string user, string password, out string error)
        {
            try
            {
                return LoginOnce(user, password, false, out error);
            }
            catch (TdsEncryptionRequiredException)
            {
                Reconnect();
                return LoginOnce(user, password, true, out error);
            }
        }

        private bool LoginOnce(string user, string password, bool useTls, out string error)
        {
            error = null;

            // 1) Pre-Login：默认声明不支持加密（NOT_SUP）；强制加密重试时声明 OFF（支持但默认关闭）
            SendPacket(PktPreLogin, BuildPreLogin(useTls ? (byte)0 : (byte)2));
            byte[] resp = RecvResponse();
            ParsePreLogin(resp, out byte enc, out int srvMajor, out int srvMinor);
            // ENCRYPTION 取值：0=OFF 1=ON 2=NOT_SUP 3=REQ
            if (enc == 3 && !useTls)
            {
                throw new TdsEncryptionRequiredException(); // 触发外层重连 + TLS 重试
            }
            if (useTls && (enc == 3 || enc == 1))
            {
                // 服务端强制/要求加密：Pre-Login 之后、Login7 之前在同一连接上完成 TLS 握手
                var ssl = new System.Net.Security.SslStream(new NetworkStream(sock, false), false,
                    (a, b, c, d) => true); // 弱口令审计场景常遇自签名证书，不校验证书链
                // 老版本 SQL Server 可能只支持 TLS 1.0/1.1，显式放开由操作系统协商
#pragma warning disable SYSLIB0039 // TLS 1.0/1.1 是兼容 SQL Server 2008 等老实例的必需项，有意保留
                ssl.AuthenticateAsClient(host, null,
                    System.Security.Authentication.SslProtocols.Tls12 |
                    System.Security.Authentication.SslProtocols.Tls11 |
                    System.Security.Authentication.SslProtocols.Tls, false);
#pragma warning restore SYSLIB0039
                stream = ssl;
            }

            // 2) Login7（按服务端版本协商 TDS 版本）
            SendPacket(PktLogin7, BuildLogin7(user, password, srvMajor, srvMinor));
            byte[] loginResp = RecvResponse();

            // 3) 解析响应 token 流
            bool ack = false;
            int pos = 0;
            while (pos < loginResp.Length)
            {
                byte tok = loginResp[pos++];
                if (tok == TokLoginAck)
                {
                    int len = loginResp[pos] | (loginResp[pos + 1] << 8);
                    ParseLoginAck(loginResp, pos + 2, len);
                    ack = true;
                    pos += 2 + len;
                }
                else if (tok == TokError || tok == TokInfo)
                {
                    int len = loginResp[pos] | (loginResp[pos + 1] << 8);
                    if (tok == TokError)
                    {
                        ParseError(loginResp, pos + 2, len, out int number, out string msg);
                        if (number == 18456) // 登录失败：口令错误，正常失败
                        {
                            error = number + ": " + msg;
                            return false;
                        }
                        throw new TdsAuthException(number, msg);
                    }
                    pos += 2 + len;
                }
                else if (tok == TokEnvChange)
                {
                    int len = loginResp[pos] | (loginResp[pos + 1] << 8);
                    pos += 2 + len;
                }
                else if (tok == TokDone || tok == TokDoneProc || tok == TokDoneInProc)
                {
                    break; // Done：13 字节，响应结束
                }
                else
                {
                    // 未知 token：无法可靠跳过，中止解析
                    break;
                }
            }
            if (ack) return true;
            error = "未收到 LoginAck";
            return false;
        }

        /// <summary>取服务端标识用于 Banner 展示。</summary>
        public string Banner()
        {
            return ServerVersion.Length > 0 ? "SQL Server " + ServerVersion : "SQL Server";
        }

        public void Dispose()
        {
            try { stream?.Dispose(); } catch { }
            try { sock?.Close(); } catch { }
        }

        // ===================== Pre-Login =====================

        private static byte[] BuildPreLogin(byte encryptMode)
        {
            // token 表：VERSION + ENCRYPTION + INSTOPT + THREADID + 0xFF
            byte[] version = { 16, 0, 0x03, 0xE8, 0, 0 };       // 16.0 build 1000
            byte[] encrypt = { encryptMode };                    // 2=NOT_SUP 明文优先；0=OFF 支持加密（强制加密重试用）
            byte[] inst = Encoding.ASCII.GetBytes("MSSQLSERVER\0");
            byte[] thread = { 0, 0, 0, 0 };

            byte[][] datas = { version, encrypt, inst, thread };
            byte[] tokens = { 0x00, 0x01, 0x02, 0x03 };
            int tableLen = tokens.Length * 5 + 1;

            var ms = new MemoryStream();
            int off = tableLen;
            for (int i = 0; i < tokens.Length; i++)
            {
                ms.WriteByte(tokens[i]);
                ms.WriteByte((byte)(off >> 8)); ms.WriteByte((byte)off);
                ms.WriteByte((byte)(datas[i].Length >> 8)); ms.WriteByte((byte)datas[i].Length);
                off += datas[i].Length;
            }
            ms.WriteByte(0xFF);
            foreach (var d in datas) ms.Write(d, 0, d.Length);
            return ms.ToArray();
        }

        /// <summary>解析 Pre-Login 响应：ENCRYPTION 取值 + 服务端版本（用于 TDS 版本协商）。</summary>
        private static void ParsePreLogin(byte[] resp, out byte enc, out int major, out int minor)
        {
            enc = 2; major = 0; minor = 0; // 未声明加密按不加密处理
            int pos = 0;
            while (pos + 5 <= resp.Length && resp[pos] != 0xFF)
            {
                byte token = resp[pos];
                int off = (resp[pos + 1] << 8) | resp[pos + 2];
                int len = (resp[pos + 3] << 8) | resp[pos + 4];
                if (off + len <= resp.Length)
                {
                    if (token == 0x00 && len >= 2) { major = resp[off]; minor = resp[off + 1]; }
                    if (token == 0x01 && len >= 1) { enc = resp[off]; }
                }
                pos += 5;
            }
        }

        // ===================== Login7 =====================

        private static byte[] BuildLogin7(string user, string password, int srvMajor, int srvMinor)
        {
            // TDS 版本协商：2012+(11.x)=7.4，2008R2(10.5)=7.3B，2008(10.0)=7.3A，2005(9.x)及更早=7.2
            // 向只支持 7.3 的 2008 声明 7.4 会被拒绝，故按 Pre-Login 返回的服务端版本选择
            uint tdsVer;
            bool hasFlags3; // OptionFlags3 字段为 TDS 7.3+ 才有
            if (srvMajor >= 11) { tdsVer = 0x74000004; hasFlags3 = true; }
            else if (srvMajor == 10 && srvMinor >= 50) { tdsVer = 0x730B0003; hasFlags3 = true; }
            else if (srvMajor == 10) { tdsVer = 0x730A0003; hasFlags3 = true; }
            else { tdsVer = 0x72090002; hasFlags3 = false; }

            string host = Environment.MachineName;
            string app = "SPasswordChecker";
            string server = "server";
            string lib = ".NET SqlClient";
            string db = "master";

            // 固定头 = 36(7.3+ 含 OptionFlags3) 或 35(7.2) + 9 组偏移(36) + ClientID(6)
            //        + SSPI/AtchDBFile/ChangePassword 三组 偏移+长度(12) + cbSSPILong(4)
            int dataStart = (hasFlags3 ? 36 : 35) + 36 + 6 + 12 + 4;
            var data = new MemoryStream();
            var offsets = new int[9, 2]; // [i,0]=offset(字符数/2=字节偏移) [i,1]=长度(字符数)
            void Put(int idx, string s, bool obfuscate)
            {
                offsets[idx, 0] = dataStart + (int)data.Length;
                offsets[idx, 1] = s.Length;
                byte[] b = Encoding.Unicode.GetBytes(s);
                if (obfuscate) Obfuscate(b);
                data.Write(b, 0, b.Length);
            }
            Put(0, host, false);
            Put(1, user, false);
            Put(2, password, true);
            Put(3, app, false);
            Put(4, server, false);
            Put(6, lib, false);    // CltIntName
            Put(7, "", false);     // Language
            Put(8, db, false);     // Database
            offsets[5, 0] = dataStart + (int)data.Length; offsets[5, 1] = 0; // Unused

            var ms = new MemoryStream();
            int total = dataStart + (int)data.Length;
            void W4LE(int v) { ms.WriteByte((byte)v); ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)(v >> 16)); ms.WriteByte((byte)(v >> 24)); }
            W4LE(total);
            W4LE((int)tdsVer);     // TDS 版本（按服务端协商）
            W4LE(4096);            // packet size
            W4LE(0); W4LE(0); W4LE(0); // prog ver / pid / conn id
            ms.WriteByte(0xE0);    // OptionFlags1: SET_LANG_ON | INIT_LANG_FATAL | ODBC_ON
            ms.WriteByte(0x00);    // OptionFlags2: USER_NORMAL(SQL 认证)
            ms.WriteByte(0x00);    // TypeFlags
            if (hasFlags3) ms.WriteByte(0x00); // OptionFlags3（TDS 7.3+ 才有）
            W4LE(0); W4LE(0);      // timezone / lcid
            for (int i = 0; i < 9; i++)
            {
                ms.WriteByte((byte)offsets[i, 0]); ms.WriteByte((byte)(offsets[i, 0] >> 8));
                ms.WriteByte((byte)offsets[i, 1]); ms.WriteByte((byte)(offsets[i, 1] >> 8));
            }
            ms.Write(new byte[6], 0, 6);          // ClientID（MAC，置零）
            ms.Write(new byte[12], 0, 12);        // ibSSPI/cbSSPI + ibAtchDBFile/cchAtchDBFile + ibChangePassword/cchChangePassword（6 个 USHORT=0）
            W4LE(0);                              // cbSSPILong（不可缺，否则整体错位 4 字节）
            ms.Write(data.ToArray(), 0, (int)data.Length);
            return ms.ToArray();
        }

        /// <summary>TDS 密码混淆：nibble 高低交换后 XOR 0xA5。</summary>
        private static void Obfuscate(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                data[i] = (byte)((((b << 4) | (b >> 4)) & 0xFF) ^ 0xA5);
            }
        }

        // ===================== 响应解析 =====================

        private void ParseLoginAck(byte[] d, int pos, int len)
        {
            // interface(1) + tdsver(4) + progname(b_varbyte utf16) + version(4: major minor buildhi buildlo)
            if (len < 10) return;
            int end = pos + len;
            int p = pos + 5;
            int nameLen = d[p] * 2;
            p += 1 + nameLen;
            if (p + 4 <= end)
            {
                ServerVersion = d[p] + "." + d[p + 1] + "." + ((d[p + 2] << 8) | d[p + 3]);
            }
        }

        private static void ParseError(byte[] d, int pos, int len, out int number, out string msg)
        {
            number = 0; msg = "";
            if (len < 8) return;
            number = d[pos] | (d[pos + 1] << 8) | (d[pos + 2] << 16) | (d[pos + 3] << 24);
            int state = d[pos + 4]; // 18456 时：5=用户不存在 8=密码不匹配
            int msgChars = d[pos + 6] | (d[pos + 7] << 8);
            int msgBytes = Math.Min(msgChars * 2, len - 8);
            msg = Encoding.Unicode.GetString(d, pos + 8, msgBytes) + "（state=" + state + "）";
        }

        // ===================== 包收发 =====================

        private void SendPacket(byte type, byte[] payload)
        {
            byte[] pkt = new byte[payload.Length + 8];
            pkt[0] = type;
            pkt[1] = 0x01; // EOM
            int len = pkt.Length;
            pkt[2] = (byte)(len >> 8); pkt[3] = (byte)len;
            pkt[6] = 1;    // packet id
            Buffer.BlockCopy(payload, 0, pkt, 8, payload.Length);
            if (stream != null)
            {
                stream.Write(pkt, 0, pkt.Length);
                stream.Flush();
            }
            else
            {
                sock.Send(pkt);
            }
        }

        /// <summary>收响应（可能跨多包），拼接 payload 直到 EOM。</summary>
        private byte[] RecvResponse()
        {
            var ms = new MemoryStream();
            for (; ; )
            {
                byte[] hdr = ReadExact(8);
                int len = (hdr[2] << 8) | hdr[3];
                if (len < 8 || len > 1024 * 1024)
                {
                    throw new Exception("TDS 包长度非法: " + len);
                }
                byte[] body = ReadExact(len - 8);
                ms.Write(body, 0, body.Length);
                if ((hdr[1] & 0x01) != 0) break; // EOM
            }
            return ms.ToArray();
        }

        private byte[] ReadExact(int n)
        {
            byte[] buf = new byte[n];
            int got = 0;
            while (got < n)
            {
                int r = stream != null
                    ? stream.Read(buf, got, n - got)
                    : sock.Receive(buf, got, n - got, SocketFlags.None);
                if (r <= 0)
                {
                    throw new EndOfStreamException("连接被服务端关闭");
                }
                got += r;
            }
            return buf;
        }

        internal sealed class TdsAuthException : Exception
        {
            public readonly int Number;
            public TdsAuthException(int number, string msg) : base(number + ": " + msg)
            {
                Number = number;
            }
        }

        /// <summary>服务端要求强制加密（ENCRYPTION=REQ）：抛出后由外层重连并走 TLS 重试。</summary>
        internal sealed class TdsEncryptionRequiredException : Exception
        {
        }
    }
}
