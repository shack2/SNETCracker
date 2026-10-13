using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// LDAP 弱口令检测：自实现 BER 编码的 simple bind（LDAPv3，RFC 4511）。
    /// BindRequest name = 用户名原文（支持 cn=admin,dc=... 完整 DN 或 user@domain 形式），
    /// authentication = simple 密码。BindResponse resultCode 0 成功 / 49 invalidCredentials 失败。
    /// 注：匿名空密码 bind 成功属服务端配置开放，也如实报成功（等效开放访问）。
    /// 实现 IReusableAuth：RFC 4511 允许同一连接上反复 Bind（re-bind 重置认证态），
    /// 口令错误（49）连接保持，批次模式可同连接连续尝试。
    /// </summary>
    class LDAP : CheckerBase, IReusableAuth
    {
        private readonly bool useSsl;
        private readonly string banner;
        private Stream stream;
        private int messageId;

        public LDAP()
        {
            useSsl = false;
            banner = "LDAP simple bind";
        }

        protected LDAP(bool useSsl)
        {
            this.useSsl = useSsl;
            banner = useSsl ? "LDAPS simple bind" : "LDAP simple bind";
        }

        /// <summary>建立 TCP（可选隐式 TLS）流。</summary>
        private Stream OpenStream(string ip, int port, int timeOut)
        {
            Socket s = Sock.Connect(ip, port, timeOut);
            Stream st = new NetworkStream(s, true);
            if (useSsl)
            {
                SslStream ssl = new SslStream(st, false, (a, b, c, d) => true);
                ssl.AuthenticateAsClient(ip);
                st = ssl;
            }
            st.ReadTimeout = timeOut * 1000;
            st.WriteTimeout = timeOut * 1000;
            return st;
        }

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }
            using (Stream st = OpenStream(ip, port, timeOut))
            {
                int resultCode = Bind(st, 1, username, password, out string diagMsg);
                if (resultCode == 0)
                {
                    server.isSuccess = true;
                    server.banner = banner;
                    return server;
                }
                if (resultCode == 49) // invalidCredentials
                {
                    server.isSuccess = false;
                    return server;
                }
                throw new Exception("LDAP bind 拒绝，resultCode=" + resultCode + " " + diagMsg);
            }
        }

        // ===================== IReusableAuth（批次连接复用） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            stream = OpenStream(ip, port, timeoutSec);
            messageId = 0;
        }

        public string Banner
        {
            get { return banner; }
        }

        public AuthResult TryAuth(string user, string password)
        {
            if ("空".Equals(password))
            {
                password = "";
            }
            try
            {
                messageId++;
                int resultCode = Bind(stream, messageId, user, password, out _);
                if (resultCode == 0)
                {
                    return AuthResult.Success;
                }
                if (resultCode == 49)
                {
                    return AuthResult.Failed;
                }
                // 其他结果码（如 53 unwillingToPerform）：服务端策略问题，断开由调度层重连
                return AuthResult.Closed;
            }
            catch (EndOfStreamException) { return AuthResult.Closed; }
            catch (IOException) { return AuthResult.Closed; }
            catch (SocketException) { return AuthResult.Closed; }
        }

        public void Dispose()
        {
            try { stream?.Dispose(); } catch { }
            stream = null;
        }

        // ===================== 协议编解码 =====================

        /// <summary>执行一次 simple bind，返回 resultCode。</summary>
        private static int Bind(Stream st, int msgId, string username, string password, out string diagMsg)
        {
            // BindRequest: [APPLICATION 0] SEQUENCE { version, name LDAPDN, authentication simple [0] }
            byte[] reqBody = Bin.Concat(
                new Ber.Encoder().Integer(3).ToArray(),
                new Ber.Encoder().OctetString(username).ToArray(),
                Ber.Tlv(0x80, Encoding.UTF8.GetBytes(password)));
            byte[] msg = Ber.Tlv(Ber.TagSequence, Bin.Concat(
                new Ber.Encoder().Integer(msgId).ToArray(),
                Ber.Tlv(0x60, reqBody)));

            st.Write(msg, 0, msg.Length);
            st.Flush();
            byte[] resp = ReadOneMessage(st);
            Ber.Reader r = new Ber.Reader(resp);
            if (r.Next(out Ber.Reader envelope) != Ber.TagSequence)
            {
                throw new InvalidDataException("非法 LDAP 应答");
            }
            envelope.Next(out Ber.Reader id); id.AsInteger();
            byte opTag = envelope.Next(out Ber.Reader op);
            if (opTag != 0x61) // BindResponse
            {
                throw new InvalidDataException("LDAP 应答非 BindResponse，tag=0x" + opTag.ToString("X2"));
            }
            op.Next(out Ber.Reader rc);
            int resultCode = (int)rc.AsInteger();
            op.Next(out Ber.Reader matchedDn); matchedDn.AsString();
            op.Next(out Ber.Reader diag);
            diagMsg = diag.AsString();
            return resultCode;
        }

        /// <summary>从流读一条完整 BER 消息（先读 tag+长度头，再读 body）。</summary>
        private static byte[] ReadOneMessage(Stream st)
        {
            byte[] head = Sock.ReadExact(st, 2);
            int len = head[1];
            int lenBytes = 0;
            if ((len & 0x80) != 0)
            {
                lenBytes = len & 0x7f;
                if (lenBytes < 1 || lenBytes > 4)
                {
                    throw new InvalidDataException("非法 LDAP 消息长度");
                }
                byte[] lb = Sock.ReadExact(st, lenBytes);
                len = 0;
                for (int i = 0; i < lenBytes; i++)
                {
                    len = (len << 8) | lb[i];
                }
            }
            byte[] full = new byte[2 + lenBytes + len];
            full[0] = head[0];
            full[1] = head[1];
            byte[] body = Sock.ReadExact(st, len);
            body.CopyTo(full, 2 + lenBytes);
            return full;
        }
    }
}
