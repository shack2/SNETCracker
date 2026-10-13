using System;
using System.Net;
using System.Net.Sockets;
using SMBLibrary;
using SMBLibrary.Client;
using Tools;

namespace SNETCracker.Checker
{
    /// <summary>
    /// SMB 弱口令检测（基于 SMBLibrary，支持 SMB 1.0/2.0/2.1/3.0，优先 SMB2 回退 SMB1）。
    /// </summary>
    class SMB : CheckerBase
    {
        public SMB()
        {

        }

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            try
            {
                // 先快速探测端口可达性，避免 SMBLibrary 内部连接在不可达主机上长时间阻塞
                using (var probe = new TcpClient())
                {
                    var connectTask = probe.ConnectAsync(ip, port);
                    if (!connectTask.Wait(timeOut * 1000))
                    {
                        throw new TimeoutException("SMB端口连接超时");
                    }
                }

                // 优先 SMB2/3，连接失败回退 SMB1
                NTStatus? status = TryLogin(new SMB2Client(), ip, port, username, password);
                if (status == null)
                {
                    status = TryLogin(new SMB1Client(), ip, port, username, password);
                }

                server.isSuccess = status == NTStatus.STATUS_SUCCESS;
                if (server.isSuccess)
                {
                    server.banner = "SMB登录成功";
                }
                else if (status == NTStatus.STATUS_LOGON_FAILURE)
                {
                    server.banner = "账号或密码错误";
                }
                else if (status != null)
                {
                    server.banner = status.ToString();
                }
            }
            catch (TimeoutException)
            {
                throw;
            }
            catch (Exception e)
            {
                FileTool.log("SMB检查异常 " + ip + ":" + port + " " + e.Message + e.StackTrace);
            }
            return server;
        }

        /// <summary>尝试连接并登录；连接或协议异常返回 null，否则返回服务器 NTStatus。</summary>
        private static NTStatus? TryLogin(ISMBClient client, string ip, int port, string username, string password)
        {
            try
            {
                IPAddress address = IPAddress.TryParse(ip, out var parsed) ? parsed : Dns.GetHostAddresses(ip)[0];
                bool connected = client.Connect(address, SMBTransportType.DirectTCPTransport);
                if (!connected)
                {
                    return null;
                }
                NTStatus status = client.Login("", username, password);
                try { client.Logoff(); } catch { }
                return status;
            }
            catch (Exception)
            {
                return null;
            }
            finally
            {
                try { client.Disconnect(); } catch { }
            }
        }
    }
}
