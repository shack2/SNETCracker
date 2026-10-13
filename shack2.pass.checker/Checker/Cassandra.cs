using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Cassandra 弱口令检测：自实现 CQL 二进制协议 v4（端口 9042）。
    /// STARTUP(CQL_VERSION=3.0.0) → AUTHENTICATE → AUTH_RESPONSE(PLAIN: \0user\0pass) →
    /// AUTH_SUCCESS 判成功 / ERROR(0x0100 bad credentials) 判口令错误 / READY 判免认证开放。
    /// </summary>
    class Cassandra : CheckerBase
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
                server.banner = "Cassandra (CQL v4)";

                // STARTUP：{CQL_VERSION=3.0.0}
                byte[] startupBody = Bin.Concat(
                    new byte[] { 0x00, 0x01 }, // map count=1
                    CqlString("CQL_VERSION"), CqlString("3.0.0"));
                WriteFrame(s, 0x01, startupBody);

                ReadFrame(s, out byte opcode, out byte[] body);
                if (opcode == 0x02) // READY：服务端未开认证
                {
                    server.isSuccess = true;
                    server.banner += "（无认证，开放访问）";
                    return server;
                }
                if (opcode == 0x00) // ERROR
                {
                    throw new Exception("Cassandra STARTUP 被拒: " + ReadError(body));
                }
                if (opcode != 0x03) // AUTHENTICATE
                {
                    throw new InvalidDataException("非法 Cassandra 应答 opcode=0x" + opcode.ToString("X2"));
                }
                string authenticator = ReadCqlString(body, 0);
                if (authenticator.Length > 0)
                {
                    server.banner = "Cassandra (" + authenticator + ")";
                }

                // AUTH_RESPONSE：PLAIN token \0user\0pass
                byte[] token = Encoding.UTF8.GetBytes("\0" + username + "\0" + password);
                WriteFrame(s, 0x0F, Bin.Concat(Bin.I32BE(token.Length), token));

                ReadFrame(s, out opcode, out body);
                if (opcode == 0x10) // AUTH_SUCCESS
                {
                    server.isSuccess = true;
                }
                else if (opcode == 0x00) // ERROR：0x0100 = bad credentials
                {
                    int code = Bin.ReadI32BE(body, 0);
                    if (code != 0x0100)
                    {
                        throw new Exception("Cassandra 认证异常: " + ReadError(body));
                    }
                    // 口令错误，正常失败
                }
                else
                {
                    throw new InvalidDataException("非法 Cassandra 认证应答 opcode=0x" + opcode.ToString("X2"));
                }
            }
            return server;
        }

        private static string ReadError(byte[] body)
        {
            int code = Bin.ReadI32BE(body, 0);
            return "code=0x" + code.ToString("X4") + " " + ReadCqlString(body, 4);
        }

        // ===================== CQL 帧编解码 =====================

        /// <summary>写 v4 请求帧：version 0x04, flags 0, stream 1。</summary>
        private static void WriteFrame(Socket s, byte opcode, byte[] body)
        {
            byte[] frame = Bin.Concat(
                new byte[] { 0x04, 0x00, 0x00, 0x01, opcode },
                Bin.I32BE(body.Length),
                body);
            s.Send(frame);
        }

        private static void ReadFrame(Socket s, out byte opcode, out byte[] body)
        {
            byte[] head = Sock.ReadExact(s, 9);
            if ((head[0] & 0x80) == 0)
            {
                throw new InvalidDataException("非法 Cassandra 响应帧");
            }
            opcode = head[4];
            int len = Bin.ReadI32BE(head, 5);
            if (len < 0 || len > 16 * 1024 * 1024)
            {
                throw new InvalidDataException("非法 Cassandra 帧长度 " + len);
            }
            body = Sock.ReadExact(s, len);
        }

        private static byte[] CqlString(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s);
            return Bin.Concat(new byte[] { (byte)(b.Length >> 8), (byte)b.Length }, b);
        }

        private static string ReadCqlString(byte[] data, int off)
        {
            if (off + 2 > data.Length)
            {
                return "";
            }
            int len = (data[off] << 8) | data[off + 1];
            if (off + 2 + len > data.Length)
            {
                return "";
            }
            return Encoding.UTF8.GetString(data, off + 2, len);
        }
    }
}
