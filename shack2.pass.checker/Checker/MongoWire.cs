using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// MongoDB 最小客户端：仅实现弱口令检测所需的能力 ——
    /// 握手（isMaster/hello）+ SCRAM-SHA-1 / SCRAM-SHA-256 认证 + buildInfo。
    /// 替代 MongoDB.Driver（连带 BouncyCastle/SharpCompress/ZstdSharp 约 10.8 MB IL）。
    /// BSON 编解码、OP_QUERY/OP_MSG 线协议均为手工最小实现，零第三方依赖、AOT 安全。
    /// </summary>
    internal sealed class MongoWire : IDisposable
    {
        private const int OpReply = 1;
        private const int OpQuery = 2004;
        private const int OpMsg = 2013;

        private Socket sock;
        private int reqId;

        /// <summary>握手返回的 maxWireVersion；>=6 走 OP_MSG，否则走 OP_QUERY；>=7 优先 SCRAM-SHA-256。</summary>
        public int MaxWireVersion;

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

        public void Dispose()
        {
            try { sock?.Close(); } catch { }
        }

        /// <summary>握手：OP_QUERY 发送 isMaster（OP_QUERY 上的 isMaster/hello 在所有版本均被允许，包括 5.1+ 禁用 OP_QUERY 的版本）。</summary>
        public BsonDoc Hello()
        {
            BsonDoc reply = RunQuery("admin.$cmd", BsonWriter.Doc().Int32("isMaster", 1).Bool("helloOk", true));
            if (!reply.Ok)
            {
                throw new Exception("MongoDB 握手失败: " + reply.Error);
            }
            MaxWireVersion = reply.Int("maxWireVersion");
            return reply;
        }

        /// <summary>在指定库上执行命令（自动按 wire version 选择 OP_MSG / OP_QUERY）。</summary>
        public BsonDoc Command(string db, BsonWriter cmd)
        {
            if (MaxWireVersion >= 6)
            {
                return RunMsg(cmd.Str("$db", db));
            }
            return RunQuery(db + ".$cmd", cmd);
        }

        /// <summary>SCRAM 认证；认证失败返回 false（error 为服务端错误），网络/协议异常直接抛出。</summary>
        public bool Authenticate(string user, string password, out string error)
        {
            // SCRAM-SHA-256 自 MongoDB 4.0（maxWireVersion 7）起支持
            string mech = MaxWireVersion >= 7 ? "SCRAM-SHA-256" : "SCRAM-SHA-1";
            if (ScramAuth(user, password, mech, out error))
            {
                return true;
            }
            // 服务端不支持该机制时回退另一机制
            if (error != null && error.IndexOf("mechanism", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                string alt = mech == "SCRAM-SHA-256" ? "SCRAM-SHA-1" : "SCRAM-SHA-256";
                if (ScramAuth(user, password, alt, out error))
                {
                    return true;
                }
            }
            return false;
        }

        // ---------------- SCRAM ----------------

        private bool ScramAuth(string user, string password, string mech, out string error)
        {
            error = null;
            bool sha256 = mech.EndsWith("256", StringComparison.Ordinal);
            byte[] pwd;
            if (sha256)
            {
                pwd = Encoding.UTF8.GetBytes(password);
            }
            else
            {
                // SCRAM-SHA-1 的口令材料是 md5(username + ":mongo:" + password) 的十六进制串
                using (MD5 md5 = MD5.Create())
                {
                    pwd = Encoding.UTF8.GetBytes(ToHex(md5.ComputeHash(Encoding.UTF8.GetBytes(user + ":mongo:" + password))));
                }
            }

            byte[] nonceBytes = new byte[24];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonceBytes);
            }
            string clientNonce = Convert.ToBase64String(nonceBytes);
            string bare = "n=" + EscapeName(user) + ",r=" + clientNonce;
            byte[] clientFirst = Encoding.UTF8.GetBytes("n,," + bare);

            BsonDoc r1 = Command("admin", BsonWriter.Doc()
                .Int32("saslStart", 1)
                .Str("mechanism", mech)
                .Bin("payload", clientFirst)
                .Int32("autoAuthorize", 1));
            if (!r1.Ok) { error = r1.Error; return false; }

            int convId = r1.Int("conversationId");
            string serverFirst = Encoding.UTF8.GetString(r1.Bin("payload") ?? Array.Empty<byte>());
            Dictionary<string, string> parts = ParseScram(serverFirst);
            if (!parts.TryGetValue("r", out string serverNonce) || !parts.ContainsKey("s") || !parts.ContainsKey("i"))
            {
                error = "SCRAM server-first 报文不完整: " + serverFirst;
                return false;
            }
            if (!serverNonce.StartsWith(clientNonce, StringComparison.Ordinal))
            {
                error = "服务器 nonce 校验失败";
                return false;
            }
            byte[] salt = Convert.FromBase64String(parts["s"]);
            int iter = int.Parse(parts["i"], System.Globalization.CultureInfo.InvariantCulture);

            byte[] salted = Rfc2898DeriveBytes.Pbkdf2(pwd, salt, iter,
                sha256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1, sha256 ? 32 : 20);
            byte[] clientKey = Hmac(salted, Encoding.UTF8.GetBytes("Client Key"), sha256);
            byte[] storedKey = Hash(clientKey, sha256);
            string withoutProof = "c=biws,r=" + serverNonce;   // biws = base64("n,,")
            byte[] authMsg = Encoding.UTF8.GetBytes(bare + "," + serverFirst + "," + withoutProof);
            byte[] clientSig = Hmac(storedKey, authMsg, sha256);
            byte[] proof = Xor(clientKey, clientSig);
            byte[] clientFinal = Encoding.UTF8.GetBytes(withoutProof + ",p=" + Convert.ToBase64String(proof));

            BsonDoc r2 = Command("admin", BsonWriter.Doc()
                .Int32("saslContinue", 1).Int32("conversationId", convId).Bin("payload", clientFinal));
            if (!r2.Ok) { error = r2.Error; return false; }

            // 校验服务器签名，防中间人冒充服务端
            byte[] serverKey = Hmac(salted, Encoding.UTF8.GetBytes("Server Key"), sha256);
            byte[] serverSig = Hmac(serverKey, authMsg, sha256);
            string sf = Encoding.UTF8.GetString(r2.Bin("payload") ?? Array.Empty<byte>());
            Dictionary<string, string> sfParts = ParseScram(sf);
            if (sfParts.TryGetValue("v", out string v) && v != Convert.ToBase64String(serverSig))
            {
                error = "服务器签名校验失败";
                return false;
            }

            // 服务端未内联结束会话时补一轮空交换
            bool done = r2.Bool("done");
            while (!done)
            {
                BsonDoc r3 = Command("admin", BsonWriter.Doc()
                    .Int32("saslContinue", 1).Int32("conversationId", convId).Bin("payload", Array.Empty<byte>()));
                if (!r3.Ok) { error = r3.Error; return false; }
                done = r3.Bool("done");
            }
            return true;
        }

        private static Dictionary<string, string> ParseScram(string msg)
        {
            var dict = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string part in msg.Split(','))
            {
                int eq = part.IndexOf('=');
                if (eq > 0)
                {
                    dict[part.Substring(0, eq)] = part.Substring(eq + 1);
                }
            }
            return dict;
        }

        private static string EscapeName(string name)
        {
            return name.Replace("=", "=3D").Replace(",", "=2C");
        }

        private static byte[] Hmac(byte[] key, byte[] data, bool sha256)
        {
            using (HMAC h = sha256 ? (HMAC)new HMACSHA256(key) : new HMACSHA1(key))
            {
                return h.ComputeHash(data);
            }
        }

        private static byte[] Hash(byte[] data, bool sha256)
        {
            using (HashAlgorithm h = sha256 ? (HashAlgorithm)SHA256.Create() : SHA1.Create())
            {
                return h.ComputeHash(data);
            }
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length];
            for (int i = 0; i < a.Length; i++) { r[i] = (byte)(a[i] ^ b[i]); }
            return r;
        }

        private static string ToHex(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data) { sb.Append(b.ToString("x2")); }
            return sb.ToString();
        }

        // ---------------- 线协议 ----------------

        private BsonDoc RunQuery(string ns, BsonWriter cmd)
        {
            byte[] doc = cmd.ToBytes();
            byte[] nsb = Encoding.UTF8.GetBytes(ns);
            var ms = new MemoryStream();
            WriteInt32(ms, 0);                       // flags
            ms.Write(nsb, 0, nsb.Length);
            ms.WriteByte(0);                         // fullCollectionName cstring
            WriteInt32(ms, 0);                       // numberToSkip
            WriteInt32(ms, -1);                      // numberToReturn
            ms.Write(doc, 0, doc.Length);
            Send(OpQuery, ms.ToArray());

            byte[] resp = Receive(out int op);
            if (op != OpReply)
            {
                throw new Exception("意外的响应 opCode=" + op);
            }
            // flags(4) + cursorId(8) + startingFrom(4) + numberReturned(4)
            if (BitConverter.ToInt32(resp, 16) < 1)
            {
                throw new Exception("OP_REPLY 空响应");
            }
            return BsonDoc.Parse(resp, 20);
        }

        private BsonDoc RunMsg(BsonWriter cmd)
        {
            byte[] doc = cmd.ToBytes();
            var ms = new MemoryStream();
            WriteInt32(ms, 0);                       // flagBits（不请求 checksum）
            ms.WriteByte(0);                         // section kind 0 = body
            ms.Write(doc, 0, doc.Length);
            Send(OpMsg, ms.ToArray());

            byte[] resp = Receive(out int op);
            if (op != OpMsg)
            {
                throw new Exception("意外的响应 opCode=" + op);
            }
            int pos = 4; // 跳过 flagBits
            while (pos < resp.Length)
            {
                byte kind = resp[pos++];
                if (kind == 0)
                {
                    return BsonDoc.Parse(resp, pos);
                }
                // kind 1 = 文档序列：int32 size（含自身）+ cstring 标识 + 文档
                int size = BitConverter.ToInt32(resp, pos);
                pos += size;
            }
            throw new Exception("OP_MSG 响应缺少 body 段");
        }

        private void Send(int opCode, byte[] body)
        {
            byte[] header = new byte[16];
            BitConverter.GetBytes(16 + body.Length).CopyTo(header, 0);
            BitConverter.GetBytes(++reqId).CopyTo(header, 4);
            BitConverter.GetBytes(opCode).CopyTo(header, 12);
            sock.Send(header);
            sock.Send(body);
        }

        private byte[] Receive(out int opCode)
        {
            byte[] head = new byte[16];
            ReadExact(head, 0, 16);
            int len = BitConverter.ToInt32(head, 0);
            if (len < 16 || len > 64 * 1024 * 1024)
            {
                throw new Exception("非法报文长度 " + len);
            }
            byte[] body = new byte[len - 16];
            ReadExact(body, 0, body.Length);
            opCode = BitConverter.ToInt32(head, 12);
            return body;
        }

        private void ReadExact(byte[] buf, int off, int len)
        {
            while (len > 0)
            {
                int n = sock.Receive(buf, off, len, SocketFlags.None);
                if (n <= 0)
                {
                    throw new EndOfStreamException("连接被远端关闭");
                }
                off += n;
                len -= n;
            }
        }

        private static void WriteInt32(Stream s, int v)
        {
            s.Write(BitConverter.GetBytes(v), 0, 4);
        }
    }

    /// <summary>最小 BSON 编码器（链式；ToBytes 一次性封口）。</summary>
    internal sealed class BsonWriter
    {
        private readonly MemoryStream buf = new MemoryStream();

        private BsonWriter() { }

        public static BsonWriter Doc()
        {
            return new BsonWriter();
        }

        public BsonWriter Double(string name, double v)
        {
            WriteName(0x01, name); buf.Write(BitConverter.GetBytes(v), 0, 8); return this;
        }

        public BsonWriter Str(string name, string v)
        {
            WriteName(0x02, name);
            byte[] b = Encoding.UTF8.GetBytes(v);
            WriteInt(b.Length + 1); buf.Write(b, 0, b.Length); buf.WriteByte(0);
            return this;
        }

        public BsonWriter Bool(string name, bool v)
        {
            WriteName(0x08, name); buf.WriteByte(v ? (byte)1 : (byte)0); return this;
        }

        public BsonWriter Int32(string name, int v)
        {
            WriteName(0x10, name); WriteInt(v); return this;
        }

        public BsonWriter Int64(string name, long v)
        {
            WriteName(0x12, name); buf.Write(BitConverter.GetBytes(v), 0, 8); return this;
        }

        /// <summary>二进制（subtype 固定为 0x00 generic）。</summary>
        public BsonWriter Bin(string name, byte[] data)
        {
            WriteName(0x05, name); WriteInt(data.Length); buf.WriteByte(0); buf.Write(data, 0, data.Length);
            return this;
        }

        public byte[] ToBytes()
        {
            buf.WriteByte(0);
            byte[] body = buf.ToArray();
            byte[] result = new byte[body.Length + 4];
            BitConverter.GetBytes(result.Length).CopyTo(result, 0);
            Buffer.BlockCopy(body, 0, result, 4, body.Length);
            return result;
        }

        private void WriteName(byte type, string name)
        {
            buf.WriteByte(type);
            byte[] b = Encoding.UTF8.GetBytes(name);
            buf.Write(b, 0, b.Length);
            buf.WriteByte(0);
        }

        private void WriteInt(int v)
        {
            buf.Write(BitConverter.GetBytes(v), 0, 4);
        }
    }

    /// <summary>最小 BSON 解码器（扁平字段访问；未识别类型按长度跳过）。</summary>
    internal sealed class BsonDoc
    {
        private readonly Dictionary<string, object> fields = new Dictionary<string, object>(StringComparer.Ordinal);

        public static BsonDoc Parse(byte[] data, int offset)
        {
            var doc = new BsonDoc();
            int pos = offset;
            int len = BitConverter.ToInt32(data, pos);
            int end = offset + len;
            pos += 4;
            while (pos < end)
            {
                byte type = data[pos++];
                if (type == 0) { break; }
                int nameStart = pos;
                while (data[pos] != 0) { pos++; }
                string name = Encoding.UTF8.GetString(data, nameStart, pos - nameStart);
                pos++;
                switch (type)
                {
                    case 0x01: doc.fields[name] = BitConverter.ToDouble(data, pos); pos += 8; break;
                    case 0x02: // string
                    case 0x0D: // code
                    case 0x0E: // symbol
                        int slen = BitConverter.ToInt32(data, pos); pos += 4;
                        doc.fields[name] = Encoding.UTF8.GetString(data, pos, slen - 1); pos += slen;
                        break;
                    case 0x03: // 子文档
                        int dlen = BitConverter.ToInt32(data, pos);
                        doc.fields[name] = Parse(data, pos); pos += dlen;
                        break;
                    case 0x04: // 数组 → List<object>（按数字键排序）
                        int alen = BitConverter.ToInt32(data, pos);
                        BsonDoc arr = Parse(data, pos);
                        doc.fields[name] = arr.fields
                            .OrderBy(kv => int.Parse(kv.Key, System.Globalization.CultureInfo.InvariantCulture))
                            .Select(kv => kv.Value).ToList();
                        pos += alen;
                        break;
                    case 0x05: // binary
                        int blen = BitConverter.ToInt32(data, pos); pos += 4;
                        pos++; // subtype
                        byte[] bin = new byte[blen];
                        Buffer.BlockCopy(data, pos, bin, 0, blen); pos += blen;
                        doc.fields[name] = bin;
                        break;
                    case 0x06: break;                    // undefined
                    case 0x07: pos += 12; break;         // ObjectId
                    case 0x08: doc.fields[name] = data[pos] != 0; pos++; break;
                    case 0x09: pos += 8; break;          // UTC datetime
                    case 0x0A: doc.fields[name] = null; break;
                    case 0x0B:                           // regex：两个 cstring
                        while (data[pos++] != 0) { }
                        while (data[pos++] != 0) { }
                        break;
                    case 0x10: doc.fields[name] = BitConverter.ToInt32(data, pos); pos += 4; break;
                    case 0x11: pos += 8; break;          // timestamp
                    case 0x12: doc.fields[name] = BitConverter.ToInt64(data, pos); pos += 8; break;
                    case 0x13: pos += 16; break;         // decimal128
                    case 0xFF: case 0x7F: break;         // minKey / maxKey
                    default:
                        throw new NotSupportedException("不支持的 BSON 类型 0x" + type.ToString("X2"));
                }
            }
            return doc;
        }

        public object Get(string name)
        {
            return fields.TryGetValue(name, out object v) ? v : null;
        }

        public bool Ok
        {
            get
            {
                object v = Get("ok");
                if (v is double d) { return d == 1.0; }
                if (v is bool b) { return b; }
                if (v is int i) { return i == 1; }
                return false;
            }
        }

        public string Str(string name)
        {
            return Get(name) as string ?? "";
        }

        public int Int(string name)
        {
            object v = Get(name);
            if (v is int i) { return i; }
            if (v is long l) { return (int)l; }
            if (v is double d) { return (int)d; }
            return 0;
        }

        public bool Bool(string name)
        {
            object v = Get(name);
            if (v is bool b) { return b; }
            if (v is int i) { return i != 0; }
            return false;
        }

        public byte[] Bin(string name)
        {
            return Get(name) as byte[];
        }

        /// <summary>"code errmsg" 形式的错误摘要。</summary>
        public string Error
        {
            get
            {
                string msg = Str("errmsg");
                int code = Int("code");
                return code > 0 ? code + ": " + msg : (msg.Length > 0 ? msg : "未知错误");
            }
        }
    }
}
