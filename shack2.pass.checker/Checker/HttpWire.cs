using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// 最小 HTTP/1.1 客户端：仅实现弱口令检测所需的 GET/POST + Basic 认证。
    /// 默认 keep-alive：同一连接可连续多请求（批次认证复用），服务端关闭连接时
    /// IsAlive 置 false，由调用方重连。支持 Content-Length 与 chunked 解码；
    /// 无长度信息时按 Connection: close 读到 EOF。可选隐式 TLS（HTTPS，不校验证书链）。
    /// 零第三方依赖、AOT 安全。不支持：重定向跟随、压缩编码。
    /// </summary>
    internal sealed class HttpWire : IDisposable
    {
        private Socket sock;
        private Stream ns;
        private byte[] carryBuf = new byte[0]; // 已读未消费的字节（跨响应）
        private int carryPos;
        private int carryLen;
        private string host;

        /// <summary>响应状态码（如 200/302/401）。</summary>
        public int Status;
        /// <summary>响应头（键小写）。</summary>
        public readonly Dictionary<string, string> Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>响应体（可能截断，上限 256 KB）。</summary>
        public string Body = "";
        /// <summary>连接是否仍可复用（服务端回 Connection: close 或 HTTP/1.0 短连接后为 false）。</summary>
        public bool IsAlive = true;

        public void Connect(string ip, int port, int timeoutSec)
        {
            Connect(ip, port, timeoutSec, false);
        }

        /// <summary>useSsl=true 时建立隐式 TLS（HTTPS）；审计场景容忍自签名证书。</summary>
        public void Connect(string ip, int port, int timeoutSec, bool useSsl)
        {
            host = ip + ":" + port;
            sock = Sock.Connect(ip, port, timeoutSec);
            Stream s = new NetworkStream(sock, false);
            if (useSsl)
            {
                var ssl = new System.Net.Security.SslStream(s, false, (a, b, c, d) => true);
                ssl.AuthenticateAsClient(ip);
                s = ssl;
            }
            s.ReadTimeout = timeoutSec * 1000;
            s.WriteTimeout = timeoutSec * 1000;
            ns = s;
            IsAlive = true;
        }

        /// <summary>GET 请求；user 非空时附带 Basic 认证头。</summary>
        public void Get(string path, string user, string password)
        {
            Send("GET", path, user, password, null, null);
        }

        /// <summary>POST 表单请求（application/x-www-form-urlencoded）。</summary>
        public void PostForm(string path, string formBody)
        {
            Send("POST", path, null, null, formBody, "application/x-www-form-urlencoded");
        }

        /// <summary>POST 请求；user 非空时附带 Basic 认证头，body/contentType 自定义（SOAP/JSON 等）。</summary>
        public void Post(string path, string user, string password, string body, string contentType)
        {
            Send("POST", path, user, password, body, contentType);
        }

        private void Send(string method, string path, string user, string password, string postBody, string contentType)
        {
            if (!IsAlive)
            {
                throw new IOException("连接已关闭，需重连");
            }
            var sb = new StringBuilder(512);
            sb.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(host).Append("\r\n");
            sb.Append("User-Agent: SNETCracker\r\n");
            sb.Append("Accept: */*\r\n");
            if (user != null)
            {
                string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + (password ?? "")));
                sb.Append("Authorization: Basic ").Append(b64).Append("\r\n");
            }
            if (postBody != null)
            {
                byte[] pb = Encoding.UTF8.GetBytes(postBody);
                sb.Append("Content-Type: ").Append(contentType).Append("\r\n");
                sb.Append("Content-Length: ").Append(pb.Length).Append("\r\n");
            }
            sb.Append("\r\n");
            byte[] head = Encoding.ASCII.GetBytes(sb.ToString());
            ns.Write(head, 0, head.Length);
            if (postBody != null)
            {
                byte[] pb = Encoding.UTF8.GetBytes(postBody);
                ns.Write(pb, 0, pb.Length);
            }
            ns.Flush();
            ReadResponse();
        }

        // ===================== 响应读取（keep-alive 需按长度精确消费） =====================

        private void ReadResponse()
        {
            Status = 0;
            Headers.Clear();
            Body = "";

            byte[] headRaw = ReadUntilHeaderEnd();
            string headText = Encoding.ASCII.GetString(headRaw);
            string[] lines = headText.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length > 0)
            {
                string[] parts = lines[0].Split(' ');
                if (parts.Length >= 2)
                {
                    int.TryParse(parts[1], out int code);
                    Status = code;
                }
            }
            if (Status == 0)
            {
                IsAlive = false;
                throw new Exception("非 HTTP 应答");
            }
            for (int i = 1; i < lines.Length; i++)
            {
                int colon = lines[i].IndexOf(':');
                if (colon > 0)
                {
                    Headers[lines[i].Substring(0, colon).Trim()] = lines[i].Substring(colon + 1).Trim();
                }
            }

            // 连接复用性：HTTP/1.0 或显式 close → 本响应后连接作废
            string conn = Header("Connection");
            if (lines[0].StartsWith("HTTP/1.0", StringComparison.Ordinal)
                || conn.Equals("close", StringComparison.OrdinalIgnoreCase))
            {
                IsAlive = false;
            }

            // 无主体的状态码直接结束
            if (Status == 204 || Status == 304 || Status / 100 == 1)
            {
                return;
            }

            string transferEncoding = Header("Transfer-Encoding");
            string contentLength = Header("Content-Length");
            if (transferEncoding.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Body = Encoding.UTF8.GetString(ReadChunked());
            }
            else if (contentLength.Length > 0 && int.TryParse(contentLength, out int n))
            {
                if (n > 0)
                {
                    Body = Encoding.UTF8.GetString(ReadBodyBytes(Math.Min(n, 256 * 1024), n));
                }
            }
            else
            {
                // 无长度信息：服务端将以关闭连接标识 body 结束
                Body = Encoding.UTF8.GetString(ReadToEof());
                IsAlive = false;
            }
        }

        /// <summary>读 n 字节主体（want=实际要取的 bytes 数，total=声明总长度，超出部分丢弃以保证下次响应边界正确）。</summary>
        private byte[] ReadBodyBytes(int want, int total)
        {
            var ms = new MemoryStream(want);
            int consumed = 0;
            while (consumed < total)
            {
                byte[] chunk = ReadSome(Math.Min(8192, total - consumed));
                consumed += chunk.Length;
                if (ms.Length < want)
                {
                    int take = (int)Math.Min(chunk.Length, want - ms.Length);
                    ms.Write(chunk, 0, take);
                }
            }
            return ms.ToArray();
        }

        private byte[] ReadChunked()
        {
            var ms = new MemoryStream();
            for (; ; )
            {
                string sizeLine = ReadLine();
                int semi = sizeLine.IndexOf(';');
                if (semi >= 0)
                {
                    sizeLine = sizeLine.Substring(0, semi);
                }
                if (!int.TryParse(sizeLine.Trim(), System.Globalization.NumberStyles.HexNumber, null, out int size))
                {
                    IsAlive = false;
                    throw new InvalidDataException("非法 chunk 长度: " + sizeLine);
                }
                if (size == 0)
                {
                    // trailer 直到空行
                    while (ReadLine().Length > 0) { }
                    break;
                }
                byte[] chunk = ReadBodyBytes(Math.Min(size, 256 * 1024), size);
                if (ms.Length < 256 * 1024)
                {
                    ms.Write(chunk, 0, (int)Math.Min(chunk.Length, 256 * 1024 - ms.Length));
                }
                ReadExactBytes(2); // 每块结尾 CRLF
            }
            return ms.ToArray();
        }

        private byte[] ReadToEof()
        {
            var ms = new MemoryStream();
            for (; ; )
            {
                byte[] chunk;
                try
                {
                    chunk = ReadSome(8192);
                }
                catch (EndOfStreamException)
                {
                    break;
                }
                ms.Write(chunk, 0, chunk.Length);
                if (ms.Length > 256 * 1024)
                {
                    break;
                }
            }
            return ms.ToArray();
        }

        // ---------------- 底层读取（带 carry 缓冲） ----------------

        private byte[] ReadUntilHeaderEnd()
        {
            var ms = new MemoryStream();
            byte[] tail = new byte[4];
            for (; ; )
            {
                int b = ReadByte();
                ms.WriteByte((byte)b);
                tail[0] = tail[1]; tail[1] = tail[2]; tail[2] = tail[3]; tail[3] = (byte)b;
                if (tail[0] == 13 && tail[1] == 10 && tail[2] == 13 && tail[3] == 10)
                {
                    break;
                }
                if (ms.Length > 64 * 1024)
                {
                    IsAlive = false;
                    throw new InvalidDataException("HTTP 头超长");
                }
            }
            return ms.ToArray();
        }

        private string ReadLine()
        {
            var ms = new MemoryStream();
            for (; ; )
            {
                int b = ReadByte();
                if (b == 10)
                {
                    break;
                }
                if (b != 13)
                {
                    ms.WriteByte((byte)b);
                }
            }
            return Encoding.ASCII.GetString(ms.ToArray());
        }

        private void ReadExactBytes(int n)
        {
            for (int i = 0; i < n; i++)
            {
                ReadByte();
            }
        }

        private int ReadByte()
        {
            if (carryLen > 0)
            {
                int b = carryBuf[carryPos];
                carryPos++;
                carryLen--;
                return b;
            }
            byte[] one = ReadSome(1);
            return one[0];
        }

        /// <summary>从缓冲/网络读至多 n 字节（至少 1 字节，EOF 抛 EndOfStreamException）。</summary>
        private byte[] ReadSome(int n)
        {
            if (carryLen > 0)
            {
                int take = Math.Min(n, carryLen);
                byte[] r = new byte[take];
                Array.Copy(carryBuf, carryPos, r, 0, take);
                carryPos += take;
                carryLen -= take;
                return r;
            }
            byte[] buf = new byte[n];
            int got = ns.Read(buf, 0, n);
            if (got <= 0)
            {
                IsAlive = false;
                throw new EndOfStreamException("连接被远端关闭");
            }
            if (got == n)
            {
                return buf;
            }
            byte[] rr = new byte[got];
            Array.Copy(buf, rr, got);
            return rr;
        }

        /// <summary>取响应头（不存在返回空串）。</summary>
        public string Header(string name)
        {
            return Headers.TryGetValue(name, out string v) ? v : "";
        }

        public void Dispose()
        {
            try { ns?.Dispose(); } catch { }
            try { sock?.Close(); } catch { }
            carryBuf = new byte[0];
            carryPos = 0;
            carryLen = 0;
            IsAlive = false;
        }
    }
}
