using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Kafka 弱口令检测：自实现 SASL/PLAIN 认证（端口 9092，Kafka ≥ 1.0，KIP-152）。
    /// ApiVersions(v0) 探测 → SaslHandshake(api17 v1, mechanism PLAIN) →
    /// SaslAuthenticate(api36 v1, auth_bytes=\0user\0pass)，error_code 0 判成功，
    /// 认证类错误（SASL_AUTHENTICATION_FAILED 等）判口令错误。
    /// </summary>
    class Kafka : CheckerBase
    {
        private int correlationId;

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }
            using (Socket s = Sock.Connect(ip, port, timeOut))
            {
                correlationId = 0;
                server.banner = "Kafka SASL/PLAIN";

                // 1. ApiVersions（探测连通性/版本，失败说明非 Kafka 或网络问题）
                byte[] resp = RoundTrip(s, 18, 0, new byte[0]);
                int err = ReadI16(resp, 0);
                if (err != 0)
                {
                    throw new Exception("Kafka ApiVersions 失败，error=" + err);
                }

                // 2. SaslHandshake PLAIN
                resp = RoundTrip(s, 17, 1, KafkaString("PLAIN"));
                err = ReadI16(resp, 0);
                if (err != 0)
                {
                    throw new Exception("Kafka 不支持 SASL/PLAIN，error=" + err);
                }

                // 3. SaslAuthenticate：auth_bytes = \0user\0pass
                byte[] token = Encoding.UTF8.GetBytes("\0" + username + "\0" + password);
                byte[] body = Bin.Concat(Bin.I32BE(token.Length), token);
                resp = RoundTrip(s, 36, 1, body);
                err = ReadI16(resp, 0);
                if (err == 0)
                {
                    server.isSuccess = true;
                }
                else if (IsAuthError(err))
                {
                    // 口令错误，正常失败
                }
                else
                {
                    throw new Exception("Kafka SASL 认证异常，error=" + err + " " + ReadNullableString(resp, 2));
                }
            }
            return server;
        }

        /// <summary>Kafka 错误码：58=SASL_AUTHENTICATION_FAILED，33=UNSUPPORTED_SASL_MECHANISM 等认证相关。</summary>
        private static bool IsAuthError(int err)
        {
            return err == 58 || err == 33 || err == 34 || err == 57;
        }

        // ===================== Kafka 协议帧 =====================

        /// <summary>发请求并读同 correlation_id 的响应体（不含长度/相关号头）。</summary>
        private byte[] RoundTrip(Socket s, short apiKey, short apiVersion, byte[] body)
        {
            correlationId++;
            // 请求头：api_key, api_version, correlation_id, client_id(NULLABLE_STRING=-1)
            byte[] payload = Bin.Concat(
                new byte[] { (byte)(apiKey >> 8), (byte)apiKey, (byte)(apiVersion >> 8), (byte)apiVersion },
                Bin.I32BE(correlationId),
                new byte[] { 0xFF, 0xFF }, // client_id = null
                body);
            byte[] frame = Bin.Concat(Bin.I32BE(payload.Length), payload);
            s.Send(frame);

            byte[] lenBuf = Sock.ReadExact(s, 4);
            int len = Bin.ReadI32BE(lenBuf, 0);
            if (len < 4 || len > 16 * 1024 * 1024)
            {
                throw new InvalidDataException("非法 Kafka 响应长度 " + len);
            }
            byte[] respPayload = Sock.ReadExact(s, len);
            int corr = Bin.ReadI32BE(respPayload, 0);
            if (corr != correlationId)
            {
                throw new InvalidDataException("Kafka 响应 correlation_id 不匹配");
            }
            byte[] bodyResp = new byte[len - 4];
            Array.Copy(respPayload, 4, bodyResp, 0, bodyResp.Length);
            return bodyResp;
        }

        private static byte[] KafkaString(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s);
            return Bin.Concat(new byte[] { (byte)(b.Length >> 8), (byte)b.Length }, b);
        }

        private static int ReadI16(byte[] data, int off)
        {
            return (short)((data[off] << 8) | data[off + 1]);
        }

        private static string ReadNullableString(byte[] data, int off)
        {
            int len = ReadI16(data, off);
            if (len <= 0 || off + 2 + len > data.Length)
            {
                return "";
            }
            return Encoding.UTF8.GetString(data, off + 2, len);
        }
    }
}
