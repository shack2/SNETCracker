using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Neo4j 弱口令检测：自实现 Bolt 握手 + HELLO basic 认证（端口 7687，Bolt v3/v4）。
    /// 握手 0x6060B017 + 版本协商（提议 4.0/3.0）→ HELLO {scheme=basic, principal, credentials} →
    /// SUCCESS(0x70) 判成功 / FAILURE(0x7F, Unauthorized) 判口令错误。
    /// PackStream 仅实现 string/map 两种类型（HELLO 消息足够）。
    /// </summary>
    class Neo4j : CheckerBase
    {
        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }
            using (Socket s = Sock.Connect(ip, port, timeOut))
            {
                server.banner = "Neo4j (Bolt)";

                // 握手：magic + 4 个版本提议（4.0、3.0，其余 0 填充）
                byte[] handshake = Bin.Concat(
                    new byte[] { 0x60, 0x60, 0xB0, 0x17 },
                    new byte[] { 0x00, 0x00, 0x00, 0x04 }, // Bolt 4.0
                    new byte[] { 0x00, 0x00, 0x00, 0x03 }, // Bolt 3.0
                    new byte[4], new byte[4]);
                s.Send(handshake);
                byte[] chosen = Sock.ReadExact(s, 4);
                if (chosen[0] == 0 && chosen[1] == 0 && chosen[2] == 0 && chosen[3] == 0)
                {
                    throw new Exception("Neo4j Bolt 版本协商失败");
                }

                // HELLO {scheme:"basic", principal:user, credentials:pass, user_agent:"spc-audit/1.0"}
                byte[] hello = Pack(
                    StructMsg(0x01,
                        PackMap(
                            PackStr("scheme"), PackStr("basic"),
                            PackStr("principal"), PackStr(username),
                            PackStr("credentials"), PackStr(password),
                            PackStr("user_agent"), PackStr("spc-audit/1.0"))));
                s.Send(hello);

                byte[] resp = ReadMessage(s);
                if (resp.Length >= 2 && resp[1] == 0x70) // SUCCESS
                {
                    server.isSuccess = true;
                    string agent = ExtractAscii(resp, "Neo4j/");
                    if (agent.Length > 0)
                    {
                        server.banner = agent;
                    }
                }
                else if (resp.Length >= 2 && resp[1] == 0x7F) // FAILURE（含 Unauthorized）
                {
                    // 口令错误，正常失败
                }
                else
                {
                    throw new InvalidDataException("非法 Bolt 应答");
                }
            }
            return server;
        }

        // ===================== Bolt 消息分块 =====================

        /// <summary>按 Bolt chunking 封装消息（单 chunk + 00 00 结束）。</summary>
        private static byte[] Pack(byte[] msg)
        {
            return Bin.Concat(new byte[] { (byte)(msg.Length >> 8), (byte)msg.Length }, msg, new byte[] { 0x00, 0x00 });
        }

        /// <summary>读一个完整消息（拼接 chunk 到 00 00）。</summary>
        private static byte[] ReadMessage(Socket s)
        {
            var ms = new MemoryStream();
            while (true)
            {
                byte[] lenBuf = Sock.ReadExact(s, 2);
                int len = (lenBuf[0] << 8) | lenBuf[1];
                if (len == 0)
                {
                    break;
                }
                byte[] chunk = Sock.ReadExact(s, len);
                ms.Write(chunk, 0, chunk.Length);
            }
            return ms.ToArray();
        }

        // ===================== PackStream 迷你编码 =====================

        private static byte[] StructMsg(byte signature, byte[] fields)
        {
            return Bin.Concat(new byte[] { 0xB1, signature }, fields);
        }

        private static byte[] PackStr(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s);
            if (b.Length < 16)
            {
                return Bin.Concat(new byte[] { (byte)(0x80 | b.Length) }, b);
            }
            if (b.Length < 256)
            {
                return Bin.Concat(new byte[] { 0xD0, (byte)b.Length }, b);
            }
            return Bin.Concat(new byte[] { 0xD1, (byte)(b.Length >> 8), (byte)b.Length }, b);
        }

        private static byte[] PackMap(params byte[][] entries)
        {
            int count = entries.Length / 2;
            byte[] body = Bin.Concat(entries);
            if (count < 16)
            {
                return Bin.Concat(new byte[] { (byte)(0xA0 | count) }, body);
            }
            return Bin.Concat(new byte[] { 0xD8, (byte)count }, body);
        }

        /// <summary>从 SUCCESS 元数据里粗提取 "Neo4j/x.y.z" 服务标识。</summary>
        private static string ExtractAscii(byte[] data, string prefix)
        {
            string text = Encoding.ASCII.GetString(data);
            int i = text.IndexOf(prefix, StringComparison.Ordinal);
            if (i < 0)
            {
                return "";
            }
            int e = i;
            while (e < text.Length && (char.IsLetterOrDigit(text[e]) || text[e] == '.' || text[e] == '/' || text[e] == '-'))
            {
                e++;
            }
            return text.Substring(i, e - i);
        }
    }
}
