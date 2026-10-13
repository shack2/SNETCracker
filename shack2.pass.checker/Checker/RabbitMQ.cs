using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// RabbitMQ 弱口令检测：自实现 AMQP 0-9-1 握手（端口 5672）。
    /// 协议头 "AMQP\0\0\9\1" → connection.start → connection.start-ok(PLAIN: \0user\0pass) →
    /// connection.tune 判认证成功；connection.close(530 ACCESS_REFUSED) 或直接断连判口令错误。
    /// </summary>
    class RabbitMQ : CheckerBase
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
                // 协议头
                s.Send(new byte[] { (byte)'A', (byte)'M', (byte)'Q', (byte)'P', 0x00, 0x00, 0x09, 0x01 });

                // connection.start（顺带从 server-properties 提取 banner）
                byte[] start = ReadMethodPayload(s, out int cls, out int mth);
                if (cls != 10 || mth != 10)
                {
                    throw new InvalidDataException($"非法 AMQP 应答 class={cls} method={mth}（期望 connection.start）");
                }
                server.banner = ExtractBanner(start);

                // connection.start-ok：空 client-properties 表 + PLAIN + \0user\0pass + en_US
                byte[] token = Encoding.UTF8.GetBytes("\0" + username + "\0" + password);
                byte[] args = Bin.Concat(
                    new byte[] { 0, 0, 0, 0 },                          // client-properties：空 field table
                    ShortStr("PLAIN"),
                    LongStr(token),
                    ShortStr("en_US"));
                WriteMethod(s, 10, 11, args);

                // 认证结果：tune=成功；close=口令错误；断连=口令错误
                try
                {
                    ReadMethodPayload(s, out cls, out mth);
                }
                catch (EndOfStreamException)
                {
                    return server; // 老版本 RabbitMQ 认证失败直接断连
                }
                if (cls == 10 && mth == 30) // connection.tune
                {
                    server.isSuccess = true;
                }
                // connection.close (10,50) 及其他 = 认证被拒
            }
            return server;
        }

        /// <summary>从 connection.start 的 server-properties 提取 product/version 作为 banner。</summary>
        private static string ExtractBanner(byte[] payload)
        {
            // payload: class u16, method u16, version-major, version-minor, server-properties(table)...
            string text = Encoding.ASCII.GetString(payload);
            string product = text.IndexOf("RabbitMQ", StringComparison.Ordinal) >= 0 ? "RabbitMQ" : "AMQP 0-9-1";
            // 粗提取 version 字段值（短名 + 0x53 + u32 长度 + 字符串）
            int vi = IndexOfAscii(payload, "version");
            if (vi > 0 && vi + 7 + 4 < payload.Length && payload[vi + 7] == 0x53)
            {
                int len = Bin.ReadI32BE(payload, vi + 8);
                if (len > 0 && len < 64 && vi + 12 + len <= payload.Length)
                {
                    return product + " " + Encoding.ASCII.GetString(payload, vi + 12, len);
                }
            }
            return product;
        }

        private static int IndexOfAscii(byte[] data, string s)
        {
            for (int i = 0; i + s.Length <= data.Length; i++)
            {
                int j = 0;
                while (j < s.Length && data[i + j] == (byte)s[j])
                {
                    j++;
                }
                if (j == s.Length)
                {
                    return i;
                }
            }
            return -1;
        }

        // ===================== AMQP 帧读写 =====================

        /// <summary>写一个 method frame（channel 0）。</summary>
        private static void WriteMethod(Socket s, int classId, int methodId, byte[] args)
        {
            byte[] payload = Bin.Concat(new byte[] { (byte)(classId >> 8), (byte)classId, (byte)(methodId >> 8), (byte)methodId }, args);
            byte[] frame = Bin.Concat(
                new byte[] { 0x01, 0x00, 0x00 },
                Bin.I32BE(payload.Length),
                payload,
                new byte[] { 0xCE });
            s.Send(frame);
        }

        /// <summary>读一个 method frame，返回 payload（跳过 heartbeat 等非方法帧）。</summary>
        private static byte[] ReadMethodPayload(Socket s, out int classId, out int methodId)
        {
            while (true)
            {
                byte[] head = Sock.ReadExact(s, 7);
                int size = Bin.ReadI32BE(head, 3);
                if (size < 0 || size > 1024 * 1024)
                {
                    throw new InvalidDataException("非法 AMQP 帧长度 " + size);
                }
                byte[] payload = Sock.ReadExact(s, size + 1); // + 帧尾 0xCE
                if (payload[size] != 0xCE)
                {
                    throw new InvalidDataException("非法 AMQP 帧尾");
                }
                if (head[0] != 0x01) // 非 method 帧（heartbeat 等）跳过
                {
                    continue;
                }
                classId = (payload[0] << 8) | payload[1];
                methodId = (payload[2] << 8) | payload[3];
                return payload;
            }
        }

        private static byte[] ShortStr(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s);
            return Bin.Concat(new byte[] { (byte)b.Length }, b);
        }

        private static byte[] LongStr(byte[] b)
        {
            return Bin.Concat(Bin.I32BE(b.Length), b);
        }
    }
}
