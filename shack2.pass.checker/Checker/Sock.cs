using System;
using System.IO;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Socket 公共助手：带超时的 TCP 连接 + 精确读取。
    /// 各二进制协议 checker 共用，替代此前每文件一份的 ConnectRaw/RecvExact 私有拷贝。
    /// </summary>
    internal static class Sock
    {
        /// <summary>带连接超时的 TCP 连接（NoDelay），收发超时 = timeoutSec。</summary>
        public static Socket Connect(string ip, int port, int timeoutSec)
        {
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            IAsyncResult ar = sock.BeginConnect(ip, port, null, null);
            // AsyncWaitHandle 是内核句柄，用完必须释放
            using (ar.AsyncWaitHandle)
            {
                if (!ar.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(timeoutSec)))
                {
                    try { sock.Close(); } catch { }
                    throw new TimeoutException("连接超时");
                }
                sock.EndConnect(ar);
            }
            sock.ReceiveTimeout = timeoutSec * 1000;
            sock.SendTimeout = timeoutSec * 1000;
            return sock;
        }

        /// <summary>从 Socket 精确读取 n 字节，不足抛 EndOfStreamException。</summary>
        public static byte[] ReadExact(Socket sock, int n)
        {
            byte[] buf = new byte[n];
            int off = 0;
            while (off < n)
            {
                int r = sock.Receive(buf, off, n - off, SocketFlags.None);
                if (r <= 0)
                {
                    throw new EndOfStreamException("连接被远端关闭");
                }
                off += r;
            }
            return buf;
        }

        /// <summary>从 Stream 精确读取 n 字节，不足抛 EndOfStreamException。</summary>
        public static byte[] ReadExact(Stream stream, int n)
        {
            byte[] buf = new byte[n];
            int off = 0;
            while (off < n)
            {
                int r = stream.Read(buf, off, n - off);
                if (r <= 0)
                {
                    throw new EndOfStreamException("连接被远端关闭");
                }
                off += r;
            }
            return buf;
        }
    }

    /// <summary>二进制编解码公共助手：大端读写 / 拼接 / 十六进制。</summary>
    internal static class Bin
    {
        public static int ReadI32BE(byte[] b, int off)
        {
            return (b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3];
        }

        public static void WriteI32BE(byte[] b, int off, int v)
        {
            b[off] = (byte)(v >> 24);
            b[off + 1] = (byte)(v >> 16);
            b[off + 2] = (byte)(v >> 8);
            b[off + 3] = (byte)(v & 0xff);
        }

        public static byte[] I32BE(int v)
        {
            byte[] b = new byte[4];
            WriteI32BE(b, 0, v);
            return b;
        }

        public static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (byte[] p in parts)
            {
                total += p.Length;
            }
            byte[] r = new byte[total];
            int off = 0;
            foreach (byte[] p in parts)
            {
                p.CopyTo(r, off);
                off += p.Length;
            }
            return r;
        }

        public static string ToHexLower(byte[] b)
        {
            char[] c = new char[b.Length * 2];
            const string hex = "0123456789abcdef";
            for (int i = 0; i < b.Length; i++)
            {
                c[i * 2] = hex[b[i] >> 4];
                c[i * 2 + 1] = hex[b[i] & 0xf];
            }
            return new string(c);
        }
    }
}
