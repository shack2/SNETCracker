using System;
using System.IO;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// MQTT 弱口令检测：自实现 MQTT 3.1.1 CONNECT / CONNACK（RFC-MQTT，端口 1883）。
    /// returnCode 0 = 认证通过；4(bad user/pass)/5(not authorized) = 口令错误。
    /// 每次认证一条连接（认证失败后服务端关闭会话），IoT 场景高频目标。
    /// </summary>
    class MQTT : CheckerBase
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
                s.Send(BuildConnect(username, password, "spc-audit"));
                byte[] head = Sock.ReadExact(s, 2);
                if ((head[0] & 0xF0) != 0x20 || head[1] != 2) // CONNACK 固定头 + 剩余长度 2
                {
                    throw new InvalidDataException("非法 MQTT CONNACK 应答");
                }
                byte[] body = Sock.ReadExact(s, 2);
                int rc = body[1];
                server.banner = "MQTT 3.1.1";
                if (rc == 0)
                {
                    server.isSuccess = true;
                }
                else if (rc == 4 || rc == 5)
                {
                    // 口令错误，正常失败
                }
                else
                {
                    throw new Exception("MQTT 连接被拒，returnCode=" + rc);
                }
            }
            return server;
        }

        /// <summary>构造 CONNECT 报文（MQTT 3.1.1，clean session，带用户名/密码）。</summary>
        internal static byte[] BuildConnect(string user, string pass, string clientId)
        {
            byte[] id = Utf8(clientId);
            byte[] u = Utf8(user);
            byte[] p = Utf8(pass);
            // 可变头：协议名 + 级别4 + 标志(用户名0x80|密码0x40|clean 0x02) + keep-alive 60s
            byte[] varHead = Bin.Concat(Utf8("MQTT"), new byte[] { 0x04, 0xC2, 0x00, 0x3C });
            byte[] payload = Bin.Concat(id, u, p);
            byte[] rest = Bin.Concat(varHead, payload);
            return Bin.Concat(new byte[] { 0x10 }, RemainingLength(rest.Length), rest);
        }

        /// <summary>MQTT 剩余长度 varint 编码（1~4 字节）。</summary>
        internal static byte[] RemainingLength(int len)
        {
            var ms = new MemoryStream(4);
            do
            {
                int d = len % 128;
                len /= 128;
                if (len > 0)
                {
                    d |= 0x80;
                }
                ms.WriteByte((byte)d);
            } while (len > 0);
            return ms.ToArray();
        }

        private static byte[] Utf8(string s)
        {
            byte[] b = System.Text.Encoding.UTF8.GetBytes(s ?? "");
            return Bin.Concat(new byte[] { (byte)(b.Length >> 8), (byte)b.Length }, b);
        }
    }
}
