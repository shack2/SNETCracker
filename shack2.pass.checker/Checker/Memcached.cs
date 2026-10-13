using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Memcached 弱口令检测：自实现文本协议探活 + 二进制协议 SASL PLAIN 认证。
    /// 文本模式（默认部署，无认证）：发 version，返回 VERSION x.y.z 即开放访问成功。
    /// SASL 模式（启动带 -S）：文本命令返回 ERROR，改走二进制协议
    /// SASL AUTH（opcode 0x21，mech PLAIN，body "\0user\0pass"），status 0 成功。
    /// </summary>
    class Memcached : CheckerBase
    {
        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }

            using (TextProto tp = new TextProto())
            {
                tp.Connect(ip, port, timeOut, false);

                // 文本协议探活：无认证的 memcached 会回 "VERSION x.y.z"
                tp.SendLine("version");
                string reply;
                try
                {
                    reply = tp.ReadLine();
                }
                catch (EndOfStreamException)
                {
                    // 有些 SASL 模式服务端不响应文本命令直接断连，转二进制 SASL
                    server.isSuccess = SaslAuth(ip, port, username, password, timeOut, out string ver);
                    server.banner = string.IsNullOrEmpty(ver) ? "Memcached(SASL)" : "Memcached " + ver;
                    return server;
                }

                if (reply.StartsWith("VERSION ", StringComparison.Ordinal))
                {
                    server.isSuccess = true;
                    server.banner = reply.Trim() + "（无认证，开放访问）";
                    return server;
                }

                // 文本命令被拒（ERROR 等）→ SASL 认证模式
                server.isSuccess = SaslAuth(ip, port, username, password, timeOut, out string version);
                server.banner = string.IsNullOrEmpty(version) ? "Memcached(SASL)" : "Memcached " + version;
                return server;
            }
        }

        /// <summary>二进制协议 SASL AUTH（PLAIN）。version 输出参数：能拿到则带上版本号。</summary>
        private static bool SaslAuth(string ip, int port, string user, string password, int timeOut, out string version)
        {
            version = null;
            // body = mech(key) + "\0user\0pass"
            string mech = "PLAIN";
            byte[] authBody = Encoding.UTF8.GetBytes("\0" + user + "\0" + password);
            byte[] body = new byte[mech.Length + authBody.Length];
            Encoding.ASCII.GetBytes(mech).CopyTo(body, 0);
            authBody.CopyTo(body, mech.Length);

            byte[] req = BuildBinaryRequest(0x21, mech, body); // SASL AUTH
            byte[] header = SendRecv(ip, port, req, timeOut);
            int status = (header[6] << 8) | header[7];
            if (status == 0x0000)
            {
                version = TryVersion(ip, port, timeOut);
                return true;
            }
            if (status == 0x0020 || status == 0x0005) // AUTH_ERROR / AUTH_CONTINUE(不应出现)
            {
                return false;
            }
            if (status == 0x0081) // UNKNOWN_COMMAND：不支持 SASL → 该实例未开认证
            {
                throw new Exception("服务端不支持 SASL 认证，但拒绝了文本协议命令（非标准 Memcached）");
            }
            throw new Exception("Memcached SASL 应答异常，status=0x" + status.ToString("X4"));
        }

        /// <summary>认证成功后尝试拿版本（二进制 version 命令 0x0b）。</summary>
        private static string TryVersion(string ip, int port, int timeOut)
        {
            try
            {
                byte[] req = BuildBinaryRequest(0x0b, null, null);
                byte[] resp = SendRecvFull(ip, port, req, timeOut);
                if (resp.Length >= 24 && resp[0] == 0x81 && resp[6] == 0 && resp[7] == 0)
                {
                    int bodyLen = Bin.ReadI32BE(resp, 8);
                    if (bodyLen > 0 && resp.Length >= 24 + bodyLen)
                    {
                        return Encoding.ASCII.GetString(resp, 24, bodyLen);
                    }
                }
            }
            catch { }
            return null;
        }

        private static byte[] BuildBinaryRequest(byte opcode, string key, byte[] body)
        {
            byte[] keyBytes = key == null ? new byte[0] : Encoding.ASCII.GetBytes(key);
            int bodyLen = keyBytes.Length + (body?.Length ?? 0);
            byte[] req = new byte[24 + bodyLen];
            req[0] = 0x80;                 // magic: request
            req[1] = opcode;
            req[2] = (byte)(keyBytes.Length >> 8);
            req[3] = (byte)(keyBytes.Length & 0xff);
            Bin.WriteI32BE(req, 8, bodyLen);
            if (keyBytes.Length > 0)
            {
                keyBytes.CopyTo(req, 24);
            }
            if (body != null && body.Length > 0)
            {
                body.CopyTo(req, 24 + keyBytes.Length);
            }
            return req;
        }

        /// <summary>发送请求并读取 24 字节响应头。</summary>
        private static byte[] SendRecv(string ip, int port, byte[] req, int timeOut)
        {
            using (Socket sock = Sock.Connect(ip, port, timeOut))
            {
                sock.Send(req);
                byte[] header = Sock.ReadExact(sock, 24);
                if (header[0] != 0x81)
                {
                    throw new InvalidDataException("非法 Memcached 二进制应答 magic=0x" + header[0].ToString("X2"));
                }
                return header;
            }
        }

        /// <summary>发送请求并读取完整响应（头 + body）。</summary>
        private static byte[] SendRecvFull(string ip, int port, byte[] req, int timeOut)
        {
            using (Socket sock = Sock.Connect(ip, port, timeOut))
            {
                sock.Send(req);
                byte[] header = Sock.ReadExact(sock, 24);
                if (header[0] != 0x81)
                {
                    throw new InvalidDataException("非法 Memcached 二进制应答 magic=0x" + header[0].ToString("X2"));
                }
                int bodyLen = Bin.ReadI32BE(header, 8);
                byte[] full = new byte[24 + bodyLen];
                header.CopyTo(full, 0);
                if (bodyLen > 0)
                {
                    byte[] body = Sock.ReadExact(sock, bodyLen);
                    body.CopyTo(full, 24);
                }
                return full;
            }
        }
    }
}
