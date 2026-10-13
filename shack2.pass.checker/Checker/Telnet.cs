using System;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Telnet 弱口令检测：自实现最小客户端（IAC 协商 + login/password 提示符交互）。
    /// 修复旧实现未 await 异步登录导致判定错误的问题。
    /// </summary>
    class Telnet : CheckerBase
    {
        private const byte IAC = 255;
        private const byte DONT = 254;
        private const byte DO = 253;
        private const byte WONT = 252;
        private const byte WILL = 251;
        private const byte SB = 250;
        private const byte SE = 240;

        /// <summary>数据按 byte→char 直读（等价 Latin-1），中文标记需按 GBK/UTF-8 字节模式匹配。</summary>
        private static string Bytes(params int[] bytes)
        {
            char[] c = new char[bytes.Length];
            for (int i = 0; i < bytes.Length; i++)
            {
                c[i] = (char)bytes[i];
            }
            return new string(c);
        }

        private static readonly string[] FailMarkers =
        {
            "incorrect", "failed", "denied", "invalid",
            Bytes(0xB4, 0xED, 0xCE, 0xF3),                 // 错误 (GBK)
            Bytes(0xE9, 0x94, 0x99, 0xE8, 0xAF, 0xAF),   // 错误 (UTF-8)
            Bytes(0xCA, 0xA7, 0xB0, 0xDC),               // 失败 (GBK)
            Bytes(0xE5, 0xA4, 0xB1, 0xE8, 0xB4, 0xA5),   // 失败 (UTF-8)
        };
        private static readonly string[] SuccessMarkers =
        {
            "last login", "welcome", "$ ", "# ", "> ", "~", "last unsuccessful",
            Bytes(0xBB, 0xB6, 0xD3, 0xAD),               // 欢迎 (GBK)
            Bytes(0xE6, 0xAC, 0xA2, 0xE8, 0xBF, 0x8E),   // 欢迎 (UTF-8)
        };

        public Telnet()
        {

        }

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            // 网络/协议异常直接上抛，由调用方按重试次数重试（不在此处吞异常）
            using (var client = new TcpClient())
            {
                    var async = client.BeginConnect(ip, port, null, null);
                    if (!async.AsyncWaitHandle.WaitOne(timeOut * 1000))
                    {
                        throw new TimeoutException("Telnet连接超时");
                    }
                    client.EndConnect(async);

                    NetworkStream stream = client.GetStream();

                    // 1. 等待登录提示符
                    string banner = ReadUntil(stream, new[] { "login:", "Login:", "LOGIN:", "username:", "Username:" }, timeOut * 1000);
                    if (banner == null)
                    {
                        server.banner = "未发现登录提示符";
                        return server;
                    }
                    server.banner = FirstLine(banner);
                    WriteLine(stream, username);

                    // 2. 等待密码提示符
                    string pwdPrompt = ReadUntil(stream, new[] { "assword:", "ASSWORD:" }, timeOut * 1000);
                    if (pwdPrompt == null)
                    {
                        server.banner = "未发现密码提示符";
                        return server;
                    }
                    WriteLine(stream, password);

                    // 3. 读取判定窗口：空闲 2.5 秒或到达总超时为止，避免 motd 中的符号造成误判
                    string verdict = ReadWindow(stream, timeOut * 1000, 2500);
                    string lower = verdict.ToLowerInvariant();
                    foreach (var marker in FailMarkers)
                    {
                        if (lower.Contains(marker))
                        {
                            return server; // 明确认证失败
                        }
                    }
                    foreach (var marker in SuccessMarkers)
                    {
                        if (lower.Contains(marker))
                        {
                            server.isSuccess = true;
                            return server;
                        }
                    }
                    // 窗口内无明确结论：保持失败
            }
            return server;
        }

        /// <summary>读取数据直到出现任一标记；超时返回 null。期间自动应答 IAC 协商。</summary>
        private static string ReadUntil(NetworkStream stream, string[] markers, int timeoutMs)
        {
            var sb = new StringBuilder();
            long deadline = Environment.TickCount64 + timeoutMs;
            while (Environment.TickCount64 < deadline)
            {
                int b = ReadByte(stream, 800);
                if (b < 0)
                {
                    continue; // 空闲超时，继续等到总超时
                }
                if (b == IAC)
                {
                    HandleNegotiation(stream);
                    continue;
                }
                sb.Append((char)b);
                string text = sb.ToString();
                foreach (var marker in markers)
                {
                    if (text.IndexOf(marker, StringComparison.Ordinal) >= 0)
                    {
                        return text;
                    }
                }
            }
            return null;
        }

        /// <summary>持续读取一个判定窗口：无数据空闲 idleMs 毫秒或总时长超过 totalMs 结束。</summary>
        private static string ReadWindow(NetworkStream stream, int totalMs, int idleMs)
        {
            var sb = new StringBuilder();
            long deadline = Environment.TickCount64 + totalMs;
            while (Environment.TickCount64 < deadline)
            {
                int b = ReadByte(stream, idleMs);
                if (b < 0)
                {
                    break; // 空闲超时，认为服务器已输出完毕
                }
                if (b == IAC)
                {
                    HandleNegotiation(stream);
                    continue;
                }
                sb.Append((char)b);
            }
            return sb.ToString();
        }

        /// <summary>读一个字节；超时/断开返回 -1。</summary>
        private static int ReadByte(NetworkStream stream, int timeoutMs)
        {
            try
            {
                var socket = stream.Socket;
                socket.ReceiveTimeout = timeoutMs;
                byte[] buf = new byte[1];
                int n = socket.Receive(buf, 0, 1, SocketFlags.None);
                return n == 1 ? buf[0] : -1;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>应答 Telnet IAC 协商：一律拒绝选项（DO→WONT，WILL→DONT），跳过子协商。</summary>
        private static void HandleNegotiation(NetworkStream stream)
        {
            try
            {
                int verb = ReadByte(stream, 1000);
                if (verb == DO || verb == DONT || verb == WILL || verb == WONT)
                {
                    int option = ReadByte(stream, 1000);
                    if (option < 0)
                    {
                        return;
                    }
                    if (verb == DO)
                    {
                        stream.WriteByte(IAC); stream.WriteByte(WONT); stream.WriteByte((byte)option);
                    }
                    else if (verb == WILL)
                    {
                        stream.WriteByte(IAC); stream.WriteByte(DONT); stream.WriteByte((byte)option);
                    }
                }
                else if (verb == SB)
                {
                    // 跳过子协商直到 IAC SE
                    int prev = -1, cur;
                    while ((cur = ReadByte(stream, 1000)) >= 0)
                    {
                        if (prev == IAC && cur == SE)
                        {
                            break;
                        }
                        prev = cur;
                    }
                }
            }
            catch { }
        }

        private static void WriteLine(NetworkStream stream, string text)
        {
            byte[] data = Encoding.ASCII.GetBytes(text + "\r\n");
            stream.Write(data, 0, data.Length);
        }

        private static string FirstLine(string text)
        {
            string line = text.Trim().Replace("\r", "");
            int idx = line.IndexOf('\n');
            string first = idx >= 0 ? line.Substring(0, idx).Trim() : line.Trim();
            return first.Length > 60 ? first.Substring(0, 60) : first;
        }
    }
}
