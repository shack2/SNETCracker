using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// ClickHouse 最小客户端：仅实现弱口令检测所需的能力 ——
    /// 原生 TCP 协议 Client Hello + 服务端 Hello/Exception 响应解析。
    /// 替代 clickhouse-client / 官方驱动。零第三方依赖、AOT 安全。
    /// 协议参考 ClickHouse 官方文档「Native TCP protocol」。
    /// 覆盖：ClickHouse 全版本（客户端 revision 取 54059，兼容所有 ≥ 该版本的服务端）。
    /// 不支持：SSL 端口、压缩块、查询执行（仅握手认证）。
    /// </summary>
    internal sealed class ClickHouseWire : IDisposable
    {
        // 包类型
        private const ulong ClientHello = 0;
        private const ulong ServerHello = 0;
        private const ulong ServerException = 2;

        // 客户端版本信息（仅作标识，低于 54060 可避免发送 quota key 等附加字段）
        private const ulong ClientVerMajor = 21;
        private const ulong ClientVerMinor = 8;
        private const ulong ClientRevision = 54059;

        // 认证失败相关错误码
        private const int ErrUnknownUser = 192;
        private const int ErrWrongPassword = 193;
        private const int ErrAuthenticationFailed = 516;

        private Socket sock;

        /// <summary>服务端版本（来自 Server Hello）。</summary>
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

        /// <summary>发送 Hello 完成认证；口令错误返回 false，网络/协议异常直接抛出。</summary>
        public bool Login(string user, string password, string database, out string error)
        {
            error = null;
            SendHello(user, password, database);

            ulong packetType = ReadVarint();
            if (packetType == ServerHello)
            {
                ReadHello();
                return true;
            }
            if (packetType == ServerException)
            {
                ReadException(out int code, out string message);
                if (code == ErrUnknownUser || code == ErrWrongPassword || code == ErrAuthenticationFailed)
                {
                    error = code + ": " + message;
                    return false;
                }
                throw new ChAuthException(code, message);
            }
            throw new Exception("协议响应类型异常: " + packetType);
        }

        /// <summary>取服务端标识用于 Banner 展示。</summary>
        public string Banner()
        {
            return ServerVersion.Length > 0 ? "ClickHouse " + ServerVersion : "ClickHouse";
        }

        public void Dispose()
        {
            try { sock?.Close(); } catch { }
        }

        // ===================== Hello 收发 =====================

        private void SendHello(string user, string password, string database)
        {
            var ms = new MemoryStream();
            WriteVarint(ms, ClientHello);
            WriteString(ms, "SNETCracker");
            WriteVarint(ms, ClientVerMajor);
            WriteVarint(ms, ClientVerMinor);
            WriteVarint(ms, ClientRevision);
            WriteString(ms, database);
            WriteString(ms, user);
            WriteString(ms, password);
            sock.Send(ms.ToArray());
        }

        private void ReadHello()
        {
            ReadString(); // server name
            ulong major = ReadVarint();
            ulong minor = ReadVarint();
            ReadVarint(); // server revision
            // revision >= 54420 时后面还有 timezone/display name/patch，
            // 但 patch 紧跟 revision 之后：54401+ 必带 patch（varint）
            ServerVersion = major + "." + minor;
        }

        private void ReadException(out int code, out string message)
        {
            code = ReadInt32LE();
            ReadString(); // exception name
            message = ReadString();
            ReadString(); // stack trace
            ReadByteRaw(); // has nested
        }

        // ===================== 编解码（LEB128 varint + 长度前缀字符串） =====================

        private static void WriteVarint(Stream s, ulong v)
        {
            while (v >= 0x80)
            {
                s.WriteByte((byte)(v | 0x80));
                v >>= 7;
            }
            s.WriteByte((byte)v);
        }

        private ulong ReadVarint()
        {
            ulong v = 0;
            int shift = 0;
            for (; ; )
            {
                byte b = ReadByteRaw();
                v |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
                if (shift > 63)
                {
                    throw new Exception("varint 超长");
                }
            }
            return v;
        }

        private static void WriteString(Stream s, string str)
        {
            byte[] b = Encoding.UTF8.GetBytes(str);
            WriteVarint(s, (ulong)b.Length);
            s.Write(b, 0, b.Length);
        }

        private string ReadString()
        {
            ulong len = ReadVarint();
            if (len > 1 * 1024 * 1024)
            {
                throw new Exception("字符串长度异常: " + len);
            }
            return Encoding.UTF8.GetString(ReadExact((int)len));
        }

        private int ReadInt32LE()
        {
            byte[] b = ReadExact(4);
            return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
        }

        private byte ReadByteRaw()
        {
            return ReadExact(1)[0];
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

        internal sealed class ChAuthException : Exception
        {
            public readonly int Code;
            public ChAuthException(int code, string msg) : base(code + ": " + msg)
            {
                Code = code;
            }
        }
    }
}
