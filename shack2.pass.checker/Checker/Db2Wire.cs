using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// DB2 最小客户端：仅实现弱口令检测所需的能力 ——
    /// DRDA 协议 EXCSAT + ACCSEC 探测 + SECCHK 明文口令认证（SECMEC=3）。
    /// 替代 IBM DB2 驱动（数 MB 且需本地客户端）。零第三方依赖、AOT 安全。
    /// 协议参考 IBM DRDA V5 规范与 Metasploit Rex::Proto::DRDA。
    /// 覆盖：DB2 LUW 9.x~12.x（DRDA 明文安全机制，服务端需允许 SECMEC=3）。
    /// 不支持：加密口令机制（SECMEC 9/11）、z/OS 特有流程、查询执行。
    /// </summary>
    internal sealed class Db2Wire : IDisposable
    {
        // DDM 命令/应答码点
        private const ushort EXCSAT = 0x1041;    // Exchange Server Attributes（请求）
        private const ushort ACCSEC = 0x106d;    // Access Security（请求）
        private const ushort SECCHK = 0x106e;    // Security Check（请求）
        private const ushort EXCSATRD = 0x1443;  // 服务属性应答
        private const ushort ACCSECRD = 0x14ac;  // 安全机制应答
        private const ushort SECCHKRM = 0x1219;  // 安全检查应答
        private const ushort RDBNFNRM = 0x2211;  // 数据库不存在

        // 参数码点
        private const ushort MGRLVLLS = 0x1404;  // 管理器级别列表
        private const ushort SECMEC = 0x11a2;    // 安全机制
        private const ushort RDBNAM = 0x2110;    // 数据库名（EBCDIC，18 字节定长）
        private const ushort USERID = 0x11a0;    // 用户名（EBCDIC）
        private const ushort PASSWORD = 0x11a1;  // 口令（EBCDIC）
        private const ushort SRVNAM = 0x116d;    // 实例名
        private const ushort SRVCLSNM = 0x1147;  // 平台
        private const ushort SRVRLSLV = 0x115a;  // 版本
        private const ushort SRVDGN = 0x1153;    // 诊断信息
        private const ushort SRVCOD = 0x1149;    // 严重级别
        private const ushort SECCHKCD = 0x11a4;  // 安全检查码（0=通过）

        // MGRLVLLS 固定载荷（声明 SQLAM 7 等管理器级别，DRDA 客户端通用写法）
        private static readonly byte[] MgrLvllsPayload =
        {
            0x14, 0x03, 0x00, 0x0a, 0x24, 0x07, 0x00, 0x0a,
            0x14, 0x74, 0x00, 0x05, 0x24, 0x0f, 0x00, 0x08,
            0x14, 0x40, 0x00, 0x09, 0x1c, 0x08, 0x04, 0xb8
        };

        private Socket sock;

        /// <summary>实例名（EXCSATRD.SRVNAM）。</summary>
        public string ServerName = "";
        /// <summary>平台（EXCSATRD.SRVCLSNM）。</summary>
        public string Platform = "";
        /// <summary>版本（EXCSATRD.SRVRLSLV）。</summary>
        public string Version = "";

        public void Connect(string ip, int port, int timeoutSec)
        {
            sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            IAsyncResult ar = sock.BeginConnect(ip, port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(timeoutSec)))
            {
                try { sock.Close(); } catch { }
                throw new TimeoutException("连接超时");
            }
            sock.EndConnect(ar);
            sock.ReceiveTimeout = timeoutSec * 1000;
            sock.SendTimeout = timeoutSec * 1000;
        }

        /// <summary>
        /// 探测：EXCSAT + ACCSEC。库名不存在抛 DbNotFoundException（调用方换候选库名重试）。
        /// </summary>
        public void Probe(string dbname)
        {
            var ms = new MemoryStream();
            WriteDdm(ms, 0x41, 1, EXCSAT, MkParam(MGRLVLLS, MgrLvllsPayload));
            WriteDdm(ms, 0x01, 2, ACCSEC, SecmecParam(), RdbnamParam(dbname));
            sock.Send(ms.ToArray());

            List<Ddm> reply = ReadReply();
            foreach (Ddm d in reply)
            {
                if (d.Codepoint == RDBNFNRM)
                {
                    throw new DbNotFoundException(ExtractSrvdgn(d));
                }
                if (d.Codepoint == EXCSATRD)
                {
                    foreach (Param p in d.Params)
                    {
                        if (p.Codepoint == SRVNAM) ServerName = FromEbcdic(p.Data);
                        else if (p.Codepoint == SRVCLSNM) Platform = FromEbcdic(p.Data);
                        else if (p.Codepoint == SRVRLSLV) Version = FromEbcdic(p.Data);
                    }
                }
            }
        }

        /// <summary>认证；口令错误返回 false，库名不存在抛 DbNotFoundException，其余协议异常直接抛出。</summary>
        public bool Login(string user, string password, string dbname, out string error)
        {
            error = null;
            var ms = new MemoryStream();
            // DB2 LUW 不接受探测后的第二次 ACCSEC（会回 CMDCHKRM 0x1245），直接发 SECCHK
            WriteDdm(ms, 0x01, 2, SECCHK, SecmecParam(), RdbnamParam(dbname),
                MkParam(PASSWORD, ToEbcdic(password)), MkParam(USERID, ToEbcdic(user)));
            sock.Send(ms.ToArray());

            List<Ddm> reply = ReadReply();
            bool accsecDenied = false;
            foreach (Ddm d in reply)
            {
                if (d.Codepoint == RDBNFNRM)
                {
                    throw new DbNotFoundException(ExtractSrvdgn(d));
                }
                if (d.Codepoint == SECCHKRM)
                {
                    int srvCod = -1, secChkCd = -1;
                    foreach (Param p in d.Params)
                    {
                        if (p.Codepoint == SRVCOD && p.Data.Length >= 2)
                        {
                            srvCod = (p.Data[0] << 8) | p.Data[1];
                        }
                        else if (p.Codepoint == SECCHKCD && p.Data.Length >= 1)
                        {
                            secChkCd = p.Data[0];
                        }
                    }
                    if (srvCod == 0 && secChkCd == 0)
                    {
                        return true;
                    }
                    error = "SECCHKCD=0x" + (secChkCd < 0 ? 0 : secChkCd).ToString("x2")
                        + " SRVCOD=" + (srvCod < 0 ? 0 : srvCod);
                    return false;
                }
                if (d.Codepoint == ACCSECRD)
                {
                    // 无 SECCHKRM 时 ACCSECRD 的 SECCHKCD 非零同样表示拒绝
                    foreach (Param p in d.Params)
                    {
                        if (p.Codepoint == SECCHKCD && p.Data.Length >= 1 && p.Data[0] != 0)
                        {
                            accsecDenied = true;
                            error = "SECCHKCD=0x" + p.Data[0].ToString("x2");
                        }
                    }
                }
            }
            if (accsecDenied)
            {
                return false;
            }
            throw new Exception("协议响应异常：未收到 SECCHKRM");
        }

        /// <summary>取服务端标识用于 Banner 展示。</summary>
        public string Banner()
        {
            string v = Version.Length > 0 ? " " + Version : "";
            string p = Platform.Length > 0 ? " (" + Platform + ")" : "";
            return "DB2" + v + p;
        }

        public void Dispose()
        {
            try { sock?.Close(); } catch { }
        }

        // ===================== DDM 组包 =====================

        private struct Param
        {
            public ushort Codepoint;
            public byte[] Data;
        }

        private struct Ddm
        {
            public ushort Codepoint;
            public List<Param> Params;
        }

        private static Param MkParam(ushort codepoint, byte[] data)
        {
            return new Param { Codepoint = codepoint, Data = data };
        }

        private static Param SecmecParam()
        {
            return MkParam(SECMEC, new byte[] { 0x00, 0x03 }); // 3 = 明文用户口令
        }

        private static Param RdbnamParam(string dbname)
        {
            // RDBNAM 为 18 字节定长，EBCDIC 编码、空格填充
            byte[] raw = new byte[18];
            byte[] name = Encoding.ASCII.GetBytes(dbname.Length > 18 ? dbname.Substring(0, 18) : dbname);
            for (int i = 0; i < 18; i++)
            {
                raw[i] = i < name.Length ? name[i] : (byte)0x20;
            }
            return MkParam(RDBNAM, ToEbcdic(raw));
        }

        private static void WriteDdm(Stream s, byte format, ushort correlId, ushort codepoint, params Param[] ps)
        {
            int body = 0;
            foreach (Param p in ps) body += 4 + p.Data.Length;
            int len = 10 + body;
            WriteU16(s, (ushort)len);
            s.WriteByte(0xD0);          // DSS magic
            s.WriteByte(format);
            WriteU16(s, correlId);
            WriteU16(s, (ushort)(len - 6));
            WriteU16(s, codepoint);
            foreach (Param p in ps)
            {
                WriteU16(s, (ushort)(4 + p.Data.Length));
                WriteU16(s, p.Codepoint);
                s.Write(p.Data, 0, p.Data.Length);
            }
        }

        private static void WriteU16(Stream s, ushort v)
        {
            s.WriteByte((byte)(v >> 8));
            s.WriteByte((byte)(v & 0xFF));
        }

        // ===================== 应答解析 =====================

        /// <summary>
        /// 读一轮应答中的所有 DDM：首个按 socket 超时等，后续只在数据已到达时继续（300ms 轮询）。
        /// </summary>
        private List<Ddm> ReadReply()
        {
            var result = new List<Ddm>();
            var pending = new MemoryStream();
            bool first = true;
            for (; ; )
            {
                if (!first && !sock.Poll(300000, SelectMode.SelectRead))
                {
                    break; // 后续 DDM 未在 300ms 内到达，认为本轮应答结束
                }
                first = false;
                byte[] chunk = new byte[8192];
                int r;
                try
                {
                    r = sock.Receive(chunk);
                }
                catch (SocketException)
                {
                    if (result.Count > 0) break;
                    throw;
                }
                if (r <= 0)
                {
                    if (result.Count > 0) break;
                    throw new EndOfStreamException("连接被服务端关闭");
                }
                pending.Write(chunk, 0, r);

                // 从缓冲里切完整 DDM
                byte[] buf = pending.ToArray();
                int pos = 0;
                while (pos + 10 <= buf.Length)
                {
                    int len = (buf[pos] << 8) | buf[pos + 1];
                    if (len < 10 || pos + len > buf.Length) break;
                    result.Add(ParseDdm(buf, pos, len));
                    pos += len;
                }
                pending.SetLength(0);
                if (pos < buf.Length)
                {
                    pending.Write(buf, pos, buf.Length - pos);
                }
            }
            if (result.Count == 0)
            {
                throw new Exception("未收到服务端应答");
            }
            return result;
        }

        private static Ddm ParseDdm(byte[] buf, int pos, int len)
        {
            var d = new Ddm { Codepoint = (ushort)((buf[pos + 8] << 8) | buf[pos + 9]), Params = new List<Param>() };
            int p = pos + 10, end = pos + len;
            while (p + 4 <= end)
            {
                int plen = (buf[p] << 8) | buf[p + 1];
                if (plen < 4 || p + plen > end) break;
                ushort cp = (ushort)((buf[p + 2] << 8) | buf[p + 3]);
                byte[] data = new byte[plen - 4];
                Buffer.BlockCopy(buf, p + 4, data, 0, data.Length);
                d.Params.Add(MkParam(cp, data));
                p += plen;
            }
            return d;
        }

        private static string ExtractSrvdgn(Ddm d)
        {
            foreach (Param p in d.Params)
            {
                if (p.Codepoint == SRVDGN)
                {
                    return FromEbcdic(p.Data);
                }
            }
            return "数据库不存在";
        }

        // ===================== EBCDIC(cp037) 转换（内嵌表，零依赖） =====================

        // ASCII(0x00-0x7F) → EBCDIC
        private static readonly byte[] A2E =
        {
            0,1,2,3,55,45,46,47,22,5,37,11,12,13,14,15,16,17,18,19,60,61,50,38,24,25,63,39,28,29,30,31,
            64,90,127,123,91,108,80,125,77,93,92,78,107,96,75,97,240,241,242,243,244,245,246,247,248,
            249,122,94,76,126,110,111,124,193,194,195,196,197,198,199,200,201,209,210,211,212,213,214,
            215,216,217,226,227,228,229,230,231,232,233,186,224,187,176,109,121,129,130,131,132,133,
            134,135,136,137,145,146,147,148,149,150,151,152,153,162,163,164,165,166,167,168,169,192,
            79,208,161,7
        };

        // EBCDIC(0x00-0xFF) → ASCII（不可映射的字节归为 '?'=0x3F）
        private static readonly byte[] E2A =
        {
            0,1,2,3,63,9,63,127,63,63,63,11,12,13,14,15,16,17,18,19,63,63,8,63,24,25,63,63,28,29,30,31,
            63,63,63,63,63,10,23,27,63,63,63,63,63,5,6,7,63,63,22,63,63,63,63,4,63,63,63,63,20,21,63,26,
            32,63,63,63,63,63,63,63,63,63,63,46,60,40,43,124,38,63,63,63,63,63,63,63,63,63,33,36,42,41,59,63,
            45,47,63,63,63,63,63,63,63,63,63,44,37,95,62,63,63,63,63,63,63,63,63,63,63,96,58,35,64,39,61,34,
            63,97,98,99,100,101,102,103,104,105,63,63,63,63,63,63,63,106,107,108,109,110,111,112,113,114,63,63,63,63,63,63,
            63,126,115,116,117,118,119,120,121,122,63,63,63,63,63,63,94,63,63,63,63,63,63,63,63,63,91,93,63,63,63,63,
            123,65,66,67,68,69,70,71,72,73,63,63,63,63,63,63,125,74,75,76,77,78,79,80,81,82,63,63,63,63,63,63,
            92,63,83,84,85,86,87,88,89,90,63,63,63,63,63,63,48,49,50,51,52,53,54,55,56,57,63,63,63,63,63,63
        };

        private static byte[] ToEbcdic(string s)
        {
            return ToEbcdic(Encoding.UTF8.GetBytes(s));
        }

        private static byte[] ToEbcdic(byte[] ascii)
        {
            byte[] r = new byte[ascii.Length];
            for (int i = 0; i < ascii.Length; i++)
            {
                r[i] = ascii[i] < 128 ? A2E[ascii[i]] : ascii[i]; // 非 ASCII 字节原样透传
            }
            return r;
        }

        private static string FromEbcdic(byte[] ebcdic)
        {
            var sb = new StringBuilder(ebcdic.Length);
            foreach (byte b in ebcdic)
            {
                sb.Append((char)E2A[b]);
            }
            return sb.ToString().Trim();
        }

        internal sealed class DbNotFoundException : Exception
        {
            public DbNotFoundException(string msg) : base(msg) { }
        }
    }
}
