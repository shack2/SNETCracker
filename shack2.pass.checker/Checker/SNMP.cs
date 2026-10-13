using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace SNETCracker.Checker
{
    /// <summary>
    /// SNMP v1/v2c 弱口令（community）检测：自实现 BER 编码的 GetRequest。
    /// SNMP 只有 community（口令），没有用户名 —— 字典约定：community 放密码字典，
    /// 用户名仅占位。向 sysDescr.0（1.3.6.1.2.1.1.1.0）发 GetRequest，
    /// 收到 GetResponse 且 error-status = 0 即 community 正确（v2c 错误口令无响应）。
    /// 实现 IFanOutAuth：UDP 无连接，一个超时窗口内并发扇出多个 community（各自独立 request-id），
    /// 按应答配对判定 —— N 个 community 一次等待完成，替代串行 N×超时。
    /// </summary>
    class SNMP : CheckerBase, IFanOutAuth
    {
        private const string SysDescrOid = "1.3.6.1.2.1.1.1.0";

        private UdpClient udp;
        private string banner = "SNMP";
        private int lastVersion = 1; // 最近一次有应答的版本（1=v2c, 0=v1），扇出时优先

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            if ("空".Equals(password))
            {
                password = "";
            }

            // v2c 优先，失败后 v1 兜底（老设备只支持 v1）
            for (int ver = 1; ver >= 0; ver--)
            {
                byte[] resp = TryGet(ip, port, password, ver, Environment.TickCount & 0x7fffffff, timeOut);
                if (resp == null)
                {
                    continue; // 超时：换版本
                }
                if (TryParseResponse(resp, out int errorStatus, out string sysDescr))
                {
                    server.isSuccess = true;
                    server.banner = BannerText(ver, errorStatus, sysDescr);
                    return server;
                }
            }
            server.isSuccess = false; // 全程无响应：口令错误（或服务不可达，上层重试覆盖网络抖动）
            return server;
        }

        private static string BannerText(int ver, int errorStatus, string sysDescr)
        {
            string v = "SNMPv" + (ver == 1 ? "2c" : "1");
            if (errorStatus == 0)
            {
                return v + " " + sysDescr;
            }
            // 有响应但 error-status 非 0：community 已被接受但 OID 不可读 → 仍算口令正确
            return v + "（community 通过，sysDescr 不可读，error=" + errorStatus + "）";
        }

        // ===================== IFanOutAuth（扇出批次） =====================

        public void Connect(string ip, int port, int timeoutSec)
        {
            udp = new UdpClient();
            udp.Client.ReceiveTimeout = 500;
            udp.Connect(ip, port);
            banner = "SNMP";
            lastVersion = 1;
        }

        public string Banner
        {
            get { return banner; }
        }

        public Dictionary<string, AuthResult> TryAuthMany(string user, IReadOnlyList<string> passwords)
        {
            var results = new Dictionary<string, AuthResult>(StringComparer.Ordinal);
            if (passwords.Count == 0)
            {
                return results;
            }
            // request-id → community 映射；同一 community 先 v2c 后 v1 两轮
            for (int round = 0; round < 2; round++)
            {
                int ver = round == 0 ? lastVersion : (lastVersion == 1 ? 0 : 1);
                var pending = new Dictionary<int, string>();
                int rid = Environment.TickCount & 0x3fffffff;
                foreach (string pw in passwords)
                {
                    if (results.ContainsKey(pw))
                    {
                        continue;
                    }
                    string community = "空".Equals(pw) ? "" : pw;
                    rid++;
                    pending[rid] = pw;
                    byte[] packet = BuildGetRequest(community, ver, rid);
                    try { udp.Send(packet, packet.Length); } catch (SocketException) { }
                }
                if (pending.Count == 0)
                {
                    break;
                }
                // 收集窗口：最多 2 秒，收齐提前结束
                long deadline = Environment.TickCount64 + 2000;
                while (pending.Count > 0 && Environment.TickCount64 < deadline)
                {
                    byte[] resp;
                    try
                    {
                        IPEndPoint from = new IPEndPoint(IPAddress.Any, 0);
                        resp = udp.Receive(ref from);
                    }
                    catch (SocketException)
                    {
                        continue; // 500ms 接收超时：检查截止时间再收
                    }
                    if (!TryParseResponse(resp, out int errorStatus, out string sysDescr, out int respRid))
                    {
                        continue;
                    }
                    if (pending.Remove(respRid, out string hit))
                    {
                        lastVersion = ver;
                        banner = BannerText(ver, errorStatus, sysDescr);
                        results[hit] = AuthResult.Success;
                    }
                }
                if (results.Count > 0)
                {
                    break; // 代理有应答：版本已确认，未应答的 community 即错误，不再换版本重试
                }
                // 整轮无应答：可能是版本不对（v1-only 设备），换版本再来一轮
            }
            // pending 中未应答的 community = 错误（不在 results 中，由调用方按失败处理）
            return results;
        }

        public void Dispose()
        {
            try { udp?.Dispose(); } catch { }
            udp = null;
        }

        // ===================== 协议编解码 =====================

        /// <summary>发送一次 GetRequest 并等待响应；超时返回 null。</summary>
        private static byte[] TryGet(string ip, int port, string community, int version, int requestId, int timeOut)
        {
            byte[] packet = BuildGetRequest(community, version, requestId);
            using (UdpClient u = new UdpClient())
            {
                // SNMP 代理通常应答很快：单次等待限 2 秒，错误 community 场景避免长时间空等
                u.Client.ReceiveTimeout = Math.Max(800, Math.Min(timeOut, 2) * 1000);
                u.Connect(ip, port);
                // UDP 无连接不可靠：发 2 次提高成功率
                for (int attempt = 0; attempt < 2; attempt++)
                {
                    u.Send(packet, packet.Length);
                    try
                    {
                        IPEndPoint from = new IPEndPoint(IPAddress.Any, 0);
                        return u.Receive(ref from);
                    }
                    catch (SocketException) { }
                }
                return null;
            }
        }

        private static byte[] BuildGetRequest(string community, int version, int requestId)
        {
            // VarBind: SEQUENCE { name OID, value NULL }
            byte[] varbind = Ber.Tlv(Ber.TagSequence, Bin.Concat(
                new Ber.Encoder().Oid(SysDescrOid).ToArray(),
                new Ber.Encoder().Null().ToArray()));
            // GetRequest-PDU [A0]: request-id, error-status, error-index, variable-bindings
            byte[] pduBody = Bin.Concat(
                new Ber.Encoder().Integer(requestId).ToArray(),
                new Ber.Encoder().Integer(0).ToArray(),
                new Ber.Encoder().Integer(0).ToArray(),
                Ber.Tlv(Ber.TagSequence, varbind));
            // SNMPv1/v2c-Message: SEQUENCE { version INTEGER, community OCTET STRING, PDU }
            byte[] msgBody = Bin.Concat(
                new Ber.Encoder().Integer(version).ToArray(),
                new Ber.Encoder().OctetString(community).ToArray(),
                Ber.Tlv(0xA0, pduBody));
            return Ber.Tlv(Ber.TagSequence, msgBody);
        }

        /// <summary>解析 GetResponse：提取 error-status 与第一个 VarBind 的字符串值。</summary>
        private static bool TryParseResponse(byte[] packet, out int errorStatus, out string sysDescr)
        {
            return TryParseResponse(packet, out errorStatus, out sysDescr, out _);
        }

        private static bool TryParseResponse(byte[] packet, out int errorStatus, out string sysDescr, out int requestId)
        {
            errorStatus = -1;
            sysDescr = "";
            requestId = 0;
            try
            {
                Ber.Reader r = new Ber.Reader(packet);
                if (r.Next(out Ber.Reader msg) != Ber.TagSequence)
                {
                    return false;
                }
                // version
                msg.Next(out Ber.Reader v); v.AsInteger();
                // community
                msg.Next(out Ber.Reader c); c.AsString();
                // PDU（GetResponse = 0xA2）
                byte pduTag = msg.Next(out Ber.Reader pdu);
                if ((pduTag & 0xf0) != 0xa0)
                {
                    return false;
                }
                pdu.Next(out Ber.Reader rid);
                requestId = (int)rid.AsInteger();
                pdu.Next(out Ber.Reader es);
                errorStatus = (int)es.AsInteger();
                pdu.Next(out Ber.Reader ei); ei.AsInteger();
                // variable-bindings
                pdu.Next(out Ber.Reader vbs);
                if (vbs.Next(out Ber.Reader vb) == Ber.TagSequence)
                {
                    vb.Next(out Ber.Reader oid); oid.AsBytes();
                    byte valTag = vb.Next(out Ber.Reader val);
                    if (valTag == Ber.TagOctetString)
                    {
                        sysDescr = val.AsString();
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
