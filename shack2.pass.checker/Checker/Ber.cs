using System;
using System.Collections.Generic;
using System.IO;

namespace SNETCracker.Checker
{
    /// <summary>
    /// 最小 BER 编解码：仅实现 SNMP / LDAP 认证所需的类型
    /// （SEQUENCE / INTEGER / OCTET STRING / NULL / OID / 应用类型）。
    /// 零依赖、AOT 安全；不支持长 OID 分量超过 28 位、不支持 indefinite length。
    /// </summary>
    internal static class Ber
    {
        // 常用 tag
        public const byte TagInteger = 0x02;
        public const byte TagOctetString = 0x04;
        public const byte TagNull = 0x05;
        public const byte TagOid = 0x06;
        public const byte TagSequence = 0x30;

        /// <summary>拼一个 TLV（tag + 长度 + payload），供 SNMP/LDAP 手工组装使用。</summary>
        public static byte[] Tlv(byte tag, byte[] payload)
        {
            var ms = new MemoryStream();
            ms.WriteByte(tag);
            Encoder.WriteLength(ms, payload.Length);
            ms.Write(payload, 0, payload.Length);
            return ms.ToArray();
        }

        /// <summary>BER 编码器（写入内存缓冲区）。</summary>
        internal sealed class Encoder
        {
            private readonly MemoryStream ms = new MemoryStream();

            public Encoder Tag(byte tag, Action body)
            {
                // 先编码 body 以得到长度
                Encoder inner = new Encoder();
                body();
                byte[] payload = inner.ToArray();
                ms.WriteByte(tag);
                WriteLength(ms, payload.Length);
                ms.Write(payload, 0, payload.Length);
                return this;
            }

            public Encoder Integer(long v)
            {
                byte[] raw = EncodeInteger(v);
                ms.WriteByte(TagInteger);
                WriteLength(ms, raw.Length);
                ms.Write(raw, 0, raw.Length);
                return this;
            }

            public Encoder OctetString(byte[] data)
            {
                ms.WriteByte(TagOctetString);
                WriteLength(ms, data.Length);
                ms.Write(data, 0, data.Length);
                return this;
            }

            public Encoder OctetString(string s)
            {
                return OctetString(System.Text.Encoding.UTF8.GetBytes(s));
            }

            public Encoder Null()
            {
                ms.WriteByte(TagNull);
                ms.WriteByte(0);
                return this;
            }

            public Encoder Oid(string dotted)
            {
                string[] parts = dotted.Split('.');
                if (parts.Length < 2)
                {
                    throw new ArgumentException("非法 OID: " + dotted);
                }
                var buf = new List<byte>();
                int first = int.Parse(parts[0]) * 40 + int.Parse(parts[1]);
                EncodeBase128(buf, first);
                for (int i = 2; i < parts.Length; i++)
                {
                    EncodeBase128(buf, int.Parse(parts[i]));
                }
                ms.WriteByte(TagOid);
                WriteLength(ms, buf.Count);
                ms.Write(buf.ToArray(), 0, buf.Count);
                return this;
            }

            public Encoder Raw(byte tag, byte[] payload)
            {
                ms.WriteByte(tag);
                WriteLength(ms, payload.Length);
                ms.Write(payload, 0, payload.Length);
                return this;
            }

            public byte[] ToArray()
            {
                return ms.ToArray();
            }

            private static byte[] EncodeInteger(long v)
            {
                // 最短的补码表示
                var bytes = new List<byte>();
                long x = v;
                do
                {
                    bytes.Add((byte)(x & 0xff));
                    x >>= 8;
                } while (!((x == 0 && (bytes[bytes.Count - 1] & 0x80) == 0) || (x == -1 && (bytes[bytes.Count - 1] & 0x80) != 0)));
                bytes.Reverse();
                return bytes.ToArray();
            }

            private static void EncodeBase128(List<byte> buf, int v)
            {
                // 大端 base-128，末字节最高位 0
                var tmp = new List<byte>();
                uint u = (uint)v;
                do
                {
                    tmp.Add((byte)(u & 0x7f));
                    u >>= 7;
                } while (u != 0);
                for (int i = tmp.Count - 1; i >= 0; i--)
                {
                    byte b = tmp[i];
                    if (i != 0)
                    {
                        b |= 0x80;
                    }
                    buf.Add(b);
                }
            }

            internal static void WriteLength(MemoryStream ms, int len)
            {
                if (len < 0x80)
                {
                    ms.WriteByte((byte)len);
                }
                else if (len <= 0xff)
                {
                    ms.WriteByte(0x81);
                    ms.WriteByte((byte)len);
                }
                else
                {
                    ms.WriteByte(0x82);
                    ms.WriteByte((byte)(len >> 8));
                    ms.WriteByte((byte)(len & 0xff));
                }
            }
        }

        /// <summary>BER 解码游标：读取一个 TLV。</summary>
        internal sealed class Reader
        {
            private readonly byte[] data;
            private int pos;
            private readonly int end;

            public Reader(byte[] data) : this(data, 0, data.Length) { }

            private Reader(byte[] data, int pos, int end)
            {
                this.data = data;
                this.pos = pos;
                this.end = end;
            }

            public bool HasMore
            {
                get { return pos < end; }
            }

            /// <summary>读取下一个 TLV，返回 tag；payload 为该 TLV 内容的子 Reader。</summary>
            public byte Next(out Reader payload)
            {
                if (pos >= end)
                {
                    throw new EndOfStreamException("BER 数据不足");
                }
                byte tag = data[pos++];
                int len = data[pos++];
                if ((len & 0x80) != 0)
                {
                    int n = len & 0x7f;
                    if (n < 1 || n > 4 || pos + n > end)
                    {
                        throw new InvalidDataException("非法 BER 长度");
                    }
                    len = 0;
                    for (int i = 0; i < n; i++)
                    {
                        len = (len << 8) | data[pos++];
                    }
                }
                if (len < 0 || pos + len > end)
                {
                    throw new InvalidDataException("BER 长度越界");
                }
                payload = new Reader(data, pos, pos + len);
                pos += len;
                return tag;
            }

            /// <summary>当前 Reader 内容按 INTEGER 解码。</summary>
            public long AsInteger()
            {
                if (pos >= end)
                {
                    return 0;
                }
                bool neg = (data[pos] & 0x80) != 0;
                long v = neg ? -1 : 0;
                for (int i = pos; i < end; i++)
                {
                    v = (v << 8) | data[i];
                }
                return v;
            }

            /// <summary>当前 Reader 内容按字节数组取出。</summary>
            public byte[] AsBytes()
            {
                byte[] r = new byte[end - pos];
                Array.Copy(data, pos, r, 0, r.Length);
                return r;
            }

            public string AsString()
            {
                return System.Text.Encoding.UTF8.GetString(AsBytes());
            }
        }
    }
}
