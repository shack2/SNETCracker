using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// PostgreSQL 最小客户端：仅实现弱口令检测所需的能力 ——
    /// v3 启动包 + cleartext / MD5 / SASL(SCRAM-SHA-256) 认证。
    /// 替代 Npgsql（约 1.5 MB IL，含完整类型系统/查询管道等死代码）。
    /// 协议参考 PostgreSQL 官方文档「Frontend/Backend Protocol」与 RFC 5802（SCRAM）。
    /// 零第三方依赖、AOT 安全。覆盖：PostgreSQL 7.4+（v3 协议），SCRAM 需 10+。
    /// 不支持：SSL 模式（直接明文启动包）、SCRAM-SHA-256-PLUS 通道绑定、GSS/Kerberos。
    /// </summary>
    internal sealed class PostgresWire : IDisposable
    {
        private const int Protocol30 = 196608; // 3.0

        private Socket sock;

        /// <summary>服务端版本（ParameterStatus server_version）。</summary>
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

        /// <summary>认证；口令错误返回 false（error 为服务端错误文本），网络/协议异常直接抛出。</summary>
        public bool Login(string user, string password, string database, out string error)
        {
            error = null;
            SendStartup(user, database);

            for (; ; )
            {
                char type = (char)ReadByte();
                byte[] payload = ReadExact(ReadInt32() - 4);
                switch (type)
                {
                    case 'R': // Authentication*
                        int authType = BE32(payload, 0);
                        if (authType == 0) break;           // Ok，继续等到 ReadyForQuery
                        if (authType == 3)                  // cleartext
                        {
                            SendPassword(Encoding.UTF8.GetBytes(password));
                            break;
                        }
                        if (authType == 5)                  // MD5
                        {
                            byte[] salt = new byte[4];
                            Buffer.BlockCopy(payload, 4, salt, 0, 4);
                            SendPassword(Encoding.ASCII.GetBytes(Md5Response(user, password, salt)));
                            break;
                        }
                        if (authType == 10)                 // SASL
                        {
                            try
                            {
                                DoScramSha256(payload, 4, password);
                            }
                            catch (PgAuthException pe) when (pe.SqlState == "28P01")
                            {
                                error = pe.Message;         // SCRAM 阶段的口令错误同样视为正常失败
                                return false;
                            }
                            break;
                        }
                        throw new Exception("不支持的认证方式: " + authType);
                    case 'E': // ErrorResponse
                        ParseError(payload, out string code, out string msg);
                        if (code == "28P01")                // invalid_password：口令错误，正常失败
                        {
                            error = code + ": " + msg;
                            return false;
                        }
                        throw new PgAuthException(code, msg);
                    case 'S': // ParameterStatus
                        ParseParamStatus(payload);
                        break;
                    case 'N': // NoticeResponse
                    case 'K': // BackendKeyData
                    case 'A': // NotificationResponse
                        break;
                    case 'Z': // ReadyForQuery：启动阶段收到即认证成功
                        return true;
                    default:
                        throw new Exception("协议响应类型异常: " + type);
                }
            }
        }

        /// <summary>取服务端标识用于 Banner 展示。</summary>
        public string Banner()
        {
            return ServerVersion.Length > 0 ? "PostgreSQL " + ServerVersion : "PostgreSQL";
        }

        public void Dispose()
        {
            try
            {
                if (sock != null && sock.Connected)
                {
                    sock.Send(new byte[] { (byte)'X', 0, 0, 0, 4 }); // Terminate
                }
            }
            catch { }
            try { sock?.Close(); } catch { }
        }

        // ===================== SCRAM-SHA-256（RFC 5802） =====================

        private void DoScramSha256(byte[] mechList, int offset, string password)
        {
            // 机制列表：以 \0 分隔的 cstring，空串结尾
            bool scram = false;
            int z = offset;
            while (z < mechList.Length && mechList[z] != 0)
            {
                int end = z;
                while (end < mechList.Length && mechList[end] != 0) end++;
                if (Encoding.ASCII.GetString(mechList, z, end - z) == "SCRAM-SHA-256") scram = true;
                z = end + 1;
            }
            if (!scram)
            {
                throw new Exception("服务端未提供 SCRAM-SHA-256 认证");
            }

            string clientNonce = Convert.ToBase64String(RandomBytes(18));
            string clientFirstBare = "n=,r=" + clientNonce; // PG 忽略 n=，用户名取启动包
            byte[] clientFirst = Encoding.ASCII.GetBytes("n,," + clientFirstBare);

            // SASLInitialResponse：机制名 + Int32 长度 + 内容
            byte[] mech = Encoding.ASCII.GetBytes("SCRAM-SHA-256");
            var ir = new MemoryStream();
            ir.Write(mech, 0, mech.Length); ir.WriteByte(0);
            byte[] len4 = BitConverter.GetBytes(clientFirst.Length);
            Array.Reverse(len4);
            ir.Write(len4, 0, 4);
            ir.Write(clientFirst, 0, clientFirst.Length);
            SendMessage('p', ir.ToArray());

            // SASLContinue：server-first-message
            string serverFirst = Encoding.ASCII.GetString(ExpectAuth(11));
            Dictionary<string, string> sf = ParseScram(serverFirst);
            string nonce = sf["r"];
            if (!nonce.StartsWith(clientNonce, StringComparison.Ordinal))
            {
                throw new Exception("SCRAM nonce 校验失败");
            }
            byte[] salt = Convert.FromBase64String(sf["s"]);
            int iterations = int.Parse(sf["i"]);

            byte[] salted = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, 32);
            byte[] clientKey = HmacSha256(salted, "Client Key");
            byte[] storedKey = SHA256.HashData(clientKey);

            string clientFinalBare = "c=biws,r=" + nonce;   // biws = base64("n,,")
            string authMessage = clientFirstBare + "," + serverFirst + "," + clientFinalBare;
            byte[] signature = HmacSha256(storedKey, authMessage);
            byte[] proof = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                proof[i] = (byte)(clientKey[i] ^ signature[i]);
            }
            SendMessage('p', Encoding.ASCII.GetBytes(clientFinalBare + ",p=" + Convert.ToBase64String(proof)));

            // SASLFinal：校验服务端签名（防伪服务端）
            string serverFinal = Encoding.ASCII.GetString(ExpectAuth(12));
            Dictionary<string, string> fin = ParseScram(serverFinal);
            byte[] serverKey = HmacSha256(salted, "Server Key");
            string expectV = Convert.ToBase64String(HmacSha256(serverKey, authMessage));
            if (!fin.TryGetValue("v", out string v) || v != expectV)
            {
                throw new Exception("SCRAM 服务端签名校验失败");
            }
        }

        /// <summary>读一条消息，要求是指定子类型的 Authentication 响应；返回认证数据（去掉 4 字节子类型）。</summary>
        private byte[] ExpectAuth(int subType)
        {
            char type = (char)ReadByte();
            byte[] payload = ReadExact(ReadInt32() - 4);
            if (type == 'E')
            {
                ParseError(payload, out string code, out string msg);
                throw new PgAuthException(code, msg);
            }
            if (type != 'R' || BE32(payload, 0) != subType)
            {
                throw new Exception("SCRAM 流程异常，期望 SASL 消息 " + subType);
            }
            byte[] data = new byte[payload.Length - 4];
            Buffer.BlockCopy(payload, 4, data, 0, data.Length);
            return data;
        }

        // ===================== 密码响应 =====================

        private static string Md5Response(string user, string password, byte[] salt)
        {
            string inner = Md5Hex(Encoding.UTF8.GetBytes(password + user));
            byte[] outerInput = Concat(Encoding.ASCII.GetBytes(inner), salt);
            return "md5" + Md5Hex(outerInput);
        }

        private void SendPassword(byte[] data)
        {
            // PasswordMessage：内容以 \0 结尾
            byte[] payload = new byte[data.Length + 1];
            Buffer.BlockCopy(data, 0, payload, 0, data.Length);
            SendMessage('p', payload);
        }

        // ===================== 消息收发 =====================

        private void SendStartup(string user, string database)
        {
            var ms = new MemoryStream();
            void CStr(string s) { byte[] b = Encoding.UTF8.GetBytes(s); ms.Write(b, 0, b.Length); ms.WriteByte(0); }
            ms.Write(new byte[4], 0, 4); // 长度占位
            ms.WriteByte((byte)(Protocol30 >> 24)); ms.WriteByte((byte)(Protocol30 >> 16));
            ms.WriteByte((byte)((Protocol30 >> 8) & 0xFF)); ms.WriteByte((byte)(Protocol30 & 0xFF));
            CStr("user"); CStr(user);
            CStr("database"); CStr(database);
            CStr("client_encoding"); CStr("UTF8");
            ms.WriteByte(0);
            byte[] pkt = ms.ToArray();
            int len = pkt.Length;
            pkt[0] = (byte)(len >> 24); pkt[1] = (byte)(len >> 16); pkt[2] = (byte)(len >> 8); pkt[3] = (byte)len;
            sock.Send(pkt);
        }

        private void SendMessage(char type, byte[] payload)
        {
            byte[] pkt = new byte[payload.Length + 5];
            pkt[0] = (byte)type;
            int len = payload.Length + 4;
            pkt[1] = (byte)(len >> 24); pkt[2] = (byte)(len >> 16); pkt[3] = (byte)(len >> 8); pkt[4] = (byte)len;
            Buffer.BlockCopy(payload, 0, pkt, 5, payload.Length);
            sock.Send(pkt);
        }

        private int ReadByte()
        {
            return ReadExact(1)[0];
        }

        private int ReadInt32()
        {
            return BE32(ReadExact(4), 0);
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

        // ===================== 解析与工具 =====================

        private void ParseParamStatus(byte[] payload)
        {
            // name\0 value\0
            int end = Array.IndexOf(payload, (byte)0);
            if (end <= 0) return;
            string name = Encoding.UTF8.GetString(payload, 0, end);
            int vEnd = Array.IndexOf(payload, (byte)0, end + 1);
            if (vEnd < 0) vEnd = payload.Length;
            if (name == "server_version")
            {
                ServerVersion = Encoding.UTF8.GetString(payload, end + 1, vEnd - end - 1);
            }
        }

        private static void ParseError(byte[] payload, out string code, out string msg)
        {
            code = ""; msg = "";
            int pos = 0;
            while (pos < payload.Length && payload[pos] != 0)
            {
                byte field = payload[pos++];
                int end = Array.IndexOf(payload, (byte)0, pos);
                if (end < 0) end = payload.Length;
                string val = Encoding.UTF8.GetString(payload, pos, end - pos);
                if (field == (byte)'C') code = val;
                else if (field == (byte)'M') msg = val;
                pos = end + 1;
            }
        }

        private static Dictionary<string, string> ParseScram(string msg)
        {
            var map = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string part in msg.Split(','))
            {
                int eq = part.IndexOf('=');
                if (eq > 0) map[part.Substring(0, eq)] = part.Substring(eq + 1);
            }
            return map;
        }

        internal sealed class PgAuthException : Exception
        {
            public readonly string SqlState;
            public PgAuthException(string sqlState, string msg) : base(sqlState + ": " + msg)
            {
                SqlState = sqlState;
            }
        }

        private static int BE32(byte[] d, int pos)
        {
            return (d[pos] << 24) | (d[pos + 1] << 16) | (d[pos + 2] << 8) | d[pos + 3];
        }

        private static byte[] HmacSha256(byte[] key, string data)
        {
            using (var h = new HMACSHA256(key))
            {
                return h.ComputeHash(Encoding.ASCII.GetBytes(data));
            }
        }

        private static string Md5Hex(byte[] data)
        {
            byte[] hash = MD5.HashData(data);
            var sb = new StringBuilder(32);
            foreach (byte b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
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
    }
}
