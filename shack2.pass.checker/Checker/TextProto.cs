using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// 文本行协议助手：TCP（可选隐式 TLS）+ 按行收发 + FTP 多行应答。
    /// 供 FTP / SMTP / POP3 / IMAP 等自实现检查器复用，零第三方依赖、AOT 安全。
    /// 弱口令审计场景默认可遇到自签名证书，TLS 不校验证书链。
    /// </summary>
    internal sealed class TextProto : IDisposable
    {
        private Socket sock;
        private Stream stream;   // BufferedStream 包装后的读写流（释放时会级联关闭底层 NetworkStream/SslStream）

        public void Connect(string ip, int port, int timeoutSec, bool useSsl)
        {
            sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
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

            Stream s = new NetworkStream(sock, true);
            if (useSsl)
            {
                SslStream ssl = new SslStream(s, false, (a, b, c, d) => true);
                ssl.AuthenticateAsClient(ip);
                s = ssl;
            }
            s.ReadTimeout = timeoutSec * 1000;
            s.WriteTimeout = timeoutSec * 1000;
            // 缓冲包装：ReadLine 逐字节读取时不再每字节一次 socket 调用（FTP/SMTP/POP3/IMAP/Telnet 高频）
            stream = new BufferedStream(s, 4096);
        }

        /// <summary>读一行（到 \n 为止，去掉结尾 \r\n）。</summary>
        public string ReadLine()
        {
            var sb = new StringBuilder();
            byte[] one = new byte[1];
            while (true)
            {
                int n = stream.Read(one, 0, 1);
                if (n <= 0)
                {
                    throw new EndOfStreamException("连接被远端关闭");
                }
                if (one[0] == (byte)'\n')
                {
                    break;
                }
                if (one[0] != (byte)'\r')
                {
                    sb.Append((char)one[0]);
                }
            }
            return sb.ToString();
        }

        /// <summary>精确读取 n 字节（用于 RESP bulk string 等）。</summary>
        public byte[] ReadBytes(int n)
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

        /// <summary>读 2 字节 CRLF 结尾（RESP bulk 数据后的固定 \r\n）。</summary>
        public void ReadCrlf()
        {
            byte[] crlf = ReadBytes(2);
            if (crlf[0] != (byte)'\r' || crlf[1] != (byte)'\n')
            {
                throw new InvalidDataException("协议格式错误：缺少 CRLF");
            }
        }

        public void SendLine(string line)
        {
            byte[] b = Encoding.UTF8.GetBytes(line + "\r\n");
            stream.Write(b, 0, b.Length);
            stream.Flush(); // BufferedStream：写完立即下发，避免对端等待
        }

        public void SendRaw(string data)
        {
            byte[] b = Encoding.UTF8.GetBytes(data);
            stream.Write(b, 0, b.Length);
            stream.Flush();
        }

        public void Dispose()
        {
            try { stream?.Dispose(); } catch { }
            try { sock?.Close(); } catch { }
        }

        /// <summary>
        /// 读 FTP 应答：返回 3 位状态码，text 为完整应答文本（含多行 xxx- ... xxx 结束）。
        /// </summary>
        public int ReadFtpReply(out string text)
        {
            var sb = new StringBuilder();
            string line = ReadLine();
            sb.Append(line);
            string code = line.Length >= 3 ? line.Substring(0, 3) : "";
            if (line.Length >= 4 && line[3] == '-' && code.Length == 3)
            {
                // 多行应答：直到出现 "xxx " 开头行
                while (true)
                {
                    line = ReadLine();
                    sb.Append('\n').Append(line);
                    if (line.StartsWith(code + " ", StringComparison.Ordinal))
                    {
                        break;
                    }
                }
            }
            text = sb.ToString();
            if (code.Length != 3 || !int.TryParse(code, out int rc))
            {
                throw new InvalidDataException("非法 FTP 应答: " + line);
            }
            return rc;
        }
    }
}
