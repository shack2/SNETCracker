using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SNETCracker.Checker
{
    /// <summary>
    /// VNC 弱口令检测：最小 RFB 实现，仅握手 + VNC Authentication（安全类型 2，DES 挑战认证）。
    /// VNC 协议本身无用户名概念，仅验证密码。
    /// </summary>
    class VNC : CheckerBase
    {
        public VNC()
        {

        }

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            // 网络/协议异常直接上抛，由调用方按重试次数重试（不在此处吞异常）
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                    socket.ReceiveTimeout = timeOut * 1000;
                    socket.SendTimeout = timeOut * 1000;

                    var async = socket.BeginConnect(ip, port, null, null);
                    if (!async.AsyncWaitHandle.WaitOne(timeOut * 1000))
                    {
                        throw new TimeoutException("VNC连接超时");
                    }
                    socket.EndConnect(async);

                    // 1. 读取服务器版本横幅 "RFB 003.008\n"（12 字节）
                    string banner = Encoding.ASCII.GetString(ReadExact(socket, 12));
                    server.banner = banner.Trim();

                    // 2. 回复客户端版本（统一按 3.8 握手）
                    WriteAll(socket, Encoding.ASCII.GetBytes("RFB 003.008\n"));

                    // 3. 读取服务器安全类型
                    byte[] securityTypes;
                    if (banner.StartsWith("RFB 003.003"))
                    {
                        // RFB 3.3：服务器直接返回 4 字节安全类型（0=失败 1=None 2=VNC认证）
                        uint type = ReadUInt32BigEndian(socket);
                        if (type == 0)
                        {
                            ReadConnFailReason(socket);
                            return server;
                        }
                        securityTypes = new[] { (byte)type };
                    }
                    else
                    {
                        // RFB 3.7/3.8：1 字节类型数量 + 类型列表
                        byte[] countBuf = ReadExact(socket, 1);
                        if (countBuf[0] == 0)
                        {
                            ReadConnFailReason(socket);
                            return server;
                        }
                        securityTypes = ReadExact(socket, countBuf[0]);
                    }

                    // 优先使用 VNC 认证（类型 2）验证密码；仅当服务器只提供无认证（类型 1）时才判为开放访问
                    if (Array.IndexOf(securityTypes, (byte)2) < 0)
                    {
                        if (Array.IndexOf(securityTypes, (byte)1) >= 0)
                        {
                            server.isSuccess = true;
                            server.banner = banner.Trim() + " 无认证(开放访问)";
                            return server;
                        }
                        server.banner = banner.Trim() + " 不支持的安全类型:" + string.Join(",", securityTypes);
                        return server;
                    }

                    // 4. 选择 VNC Authentication（3.3 无需回选）
                    if (!banner.StartsWith("RFB 003.003"))
                    {
                        WriteAll(socket, new byte[] { 2 });
                    }

                    // 5. 读取 16 字节挑战，DES 加密后回发
                    byte[] challenge = ReadExact(socket, 16);
                    WriteAll(socket, EncryptChallenge(password, challenge));

                    // 6. 安全结果：0=成功 1=失败 2=尝试过多
                    uint result = ReadUInt32BigEndian(socket);
                    server.isSuccess = result == 0;
            }
            return server;
        }

        /// <summary>
        /// VNC DES 挑战响应：密码截断/补零到 8 字节，每字节比特反转后作为 DES 密钥，ECB 加密 16 字节挑战。
        /// </summary>
        private static byte[] EncryptChallenge(string password, byte[] challenge)
        {
            byte[] key = new byte[8];
            byte[] pwdBytes = Encoding.ASCII.GetBytes(password ?? "");
            for (int i = 0; i < 8; i++)
            {
                key[i] = i < pwdBytes.Length ? ReverseBits(pwdBytes[i]) : (byte)0;
            }
            byte[] response = new byte[16];
            using (DES des = DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                des.Key = key;
                using (var encryptor = des.CreateEncryptor())
                {
                    encryptor.TransformBlock(challenge, 0, 8, response, 0);
                    encryptor.TransformBlock(challenge, 8, 8, response, 8);
                }
            }
            return response;
        }

        private static byte ReverseBits(byte b)
        {
            b = (byte)(((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
            b = (byte)(((b & 0xCC) >> 2) | ((b & 0x33) << 2));
            b = (byte)(((b & 0xAA) >> 1) | ((b & 0x55) << 1));
            return b;
        }

        private static byte[] ReadExact(Socket socket, int length)
        {
            byte[] buffer = new byte[length];
            int offset = 0;
            while (offset < length)
            {
                int n = socket.Receive(buffer, offset, length - offset, SocketFlags.None);
                if (n <= 0)
                {
                    throw new SocketException((int)SocketError.ConnectionReset);
                }
                offset += n;
            }
            return buffer;
        }

        private static void WriteAll(Socket socket, byte[] data)
        {
            int offset = 0;
            while (offset < data.Length)
            {
                offset += socket.Send(data, offset, data.Length - offset, SocketFlags.None);
            }
        }

        private static uint ReadUInt32BigEndian(Socket socket)
        {
            byte[] buf = ReadExact(socket, 4);
            return ((uint)buf[0] << 24) | ((uint)buf[1] << 16) | ((uint)buf[2] << 8) | buf[3];
        }

        private static void ReadConnFailReason(Socket socket)
        {
            try
            {
                uint len = ReadUInt32BigEndian(socket);
                if (len > 0 && len < 4096)
                {
                    ReadExact(socket, (int)len);
                }
            }
            catch { }
        }
    }
}
