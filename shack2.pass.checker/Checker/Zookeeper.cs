using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Zookeeper 弱口令检测：自实现 connect + exists + addAuth(digest) 二进制协议。
    /// 先无认证发 exists("/")：err=0 → world:anyone 开放访问成功；
    /// err=-102(NoAuth) → 重连后 addAuth(digest, "user:pass") 再 exists：
    /// err=0 / -101(NoNode) 成功，err=-102 或认证应答异常 → 干净失败。
    /// 注：ZK ACL 可按路径细分，本检测以根节点可读为准。
    /// </summary>
    class Zookeeper : CheckerBase
    {
        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }

            // 第一轮：无认证探测
            int err = ExistsNoAuth(ip, port, timeOut);
            if (err == 0)
            {
                server.isSuccess = true;
                server.banner = "Zookeeper（world 开放访问）";
                return server;
            }
            if (err != -102)
            {
                throw new Exception("Zookeeper exists 应答异常，err=" + err);
            }

            // 第二轮：digest 认证
            bool? ok = TryDigest(ip, port, username, password, timeOut);
            if (!ok.HasValue)
            {
                throw new Exception("Zookeeper 认证过程连接异常");
            }
            server.isSuccess = ok.Value;
            server.banner = "Zookeeper digest";
            return server;
        }

        /// <summary>连接并 exists("/")，返回 err 码（0=可读，-102=NoAuth）。</summary>
        private static int ExistsNoAuth(string ip, int port, int timeOut)
        {
            using (Socket sock = Sock.Connect(ip, port, timeOut))
            {
                NetworkStream ns = new NetworkStream(sock, false);
                ConnectHandshake(ns, timeOut);
                SendRequest(ns, xid: 1, type: 4, payload: ExistsPayload("/")); // exists
                return ReadReplyErr(ns);
            }
        }

        /// <summary>digest 认证后 exists("/")：true=通过，false=拒绝，null=协议异常。</summary>
        private static bool? TryDigest(string ip, int port, string user, string password, int timeOut)
        {
            try
            {
                using (Socket sock = Sock.Connect(ip, port, timeOut))
                {
                    NetworkStream ns = new NetworkStream(sock, false);
                    ConnectHandshake(ns, timeOut);

                    // addAuth: xid=-4, type=100, AuthPacket{type=0, scheme="digest", auth="user:pass"}
                    byte[] authPkt = Bin.Concat(
                        Bin.I32BE(0),
                        Str("digest"),
                        Buf(Encoding.UTF8.GetBytes(user + ":" + password)));
                    SendRequest(ns, xid: -4, type: 100, payload: authPkt);
                    int authErr = ReadReplyErr(ns);
                    if (authErr != 0)
                    {
                        return false; // -115 AUTHFAILED 等
                    }

                    SendRequest(ns, xid: 1, type: 4, payload: ExistsPayload("/"));
                    int err = ReadReplyErr(ns);
                    return err != -102; // 0 / -101(NoNode) 均说明已认证
                }
            }
            catch (EndOfStreamException) { return false; }  // 服务端认证失败直接断连（ZK 常见行为）
            catch (IOException) { return false; }
            catch (SocketException) { return false; }
        }

        // ===================== 协议编解码 =====================

        private static void ConnectHandshake(NetworkStream ns, int timeOut)
        {
            // connectRequest: len + protocolVersion(4) + lastZxid(8) + timeout(4) + sessionId(8) + passwdBuf(4+16 零) + readOnly(1)
            byte[] body = new byte[4 + 8 + 4 + 8 + 4 + 16 + 1];
            // protocolVersion(0-3)=0、lastZxid(4-11)=0 默认零
            Bin.WriteI32BE(body, 12, timeOut * 1000);                    // session timeout(ms)
            Bin.WriteI32BE(body, 24, 16);                                // passwd buffer 长度=16
            // passwd(28-43) 全零, readOnly(44)=0
            byte[] len = Bin.I32BE(body.Length);
            ns.Write(len, 0, 4);
            ns.Write(body, 0, body.Length);
            ns.Flush();

            // connectResponse：3.5+ 有长度前缀（len + proto + timeout + sessionId + passwdBuf [+readOnly]）；
            // 3.4- 无长度前缀，首 4 字节即 protocolVersion（恒为 0）。用首字==0 区分两种格式。
            byte[] first = Sock.ReadExact(ns, 4);
            int w = Bin.ReadI32BE(first, 0);
            byte[] resp;
            if (w == 0)
            {
                // 老格式：proto=0 已读，续读 timeout(4)+sessionId(8)+passwdLen(4)
                resp = Bin.Concat(first, Sock.ReadExact(ns, 16));
                int pl0 = Bin.ReadI32BE(resp, 16);
                if (pl0 < 0 || pl0 > 1024)
                {
                    throw new InvalidDataException("Zookeeper 握手应答异常");
                }
                if (pl0 > 0)
                {
                    Sock.ReadExact(ns, pl0);
                }
                return;
            }
            if (w < 20 || w > 4096)
            {
                throw new InvalidDataException("Zookeeper 握手应答长度异常: " + w);
            }
            resp = Sock.ReadExact(ns, w);
            int proto = Bin.ReadI32BE(resp, 0);
            if (proto < 0)
            {
                throw new InvalidDataException("Zookeeper 握手被拒（protocolVersion=" + proto + "）");
            }
            int pl = Bin.ReadI32BE(resp, 16);
            if (pl < 0 || pl > 1024 || 20 + pl > resp.Length)
            {
                throw new InvalidDataException("Zookeeper 握手应答异常");
            }
            // passwd 与可选 readOnly 已在长度界内，无需再读
        }

        private static byte[] ExistsPayload(string path)
        {
            return Bin.Concat(Str(path), new byte[] { 0 }); // watch=false
        }

        private static void SendRequest(NetworkStream ns, int xid, int type, byte[] payload)
        {
            byte[] body = Bin.Concat(Bin.I32BE(xid), Bin.I32BE(type), payload);
            byte[] len = Bin.I32BE(body.Length);
            ns.Write(len, 0, 4);
            ns.Write(body, 0, body.Length);
            ns.Flush();
        }

        /// <summary>读应答头（4 字节长度 + xid + zxid(8) + err），返回 err。</summary>
        private static int ReadReplyErr(NetworkStream ns)
        {
            byte[] lenB = Sock.ReadExact(ns, 4);
            int len = Bin.ReadI32BE(lenB, 0);
            if (len < 16 || len > 1024 * 1024)
            {
                throw new InvalidDataException("Zookeeper 应答长度异常: " + len);
            }
            byte[] body = Sock.ReadExact(ns, len);
            return Bin.ReadI32BE(body, 12); // xid(0-3) zxid(4-11) err(12-15)
        }

        private static byte[] Str(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s);
            return Bin.Concat(Bin.I32BE(b.Length), b);
        }

        private static byte[] Buf(byte[] b)
        {
            return Bin.Concat(Bin.I32BE(b.Length), b);
        }
    }
}
