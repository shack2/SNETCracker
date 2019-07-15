using Chilkat;
using Rebex.Net;
using SharpCifs;
using SharpCifs.Smb;
using System;
using System.Threading;
using Tools;

namespace SNETCracker.Model
{
    class CrackSMB : CrackService
    {
        public CrackSMB()
        {

        }

        public override Server creack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            try
            {
                if ("".Equals("空"))
                {
                    password = "";
                }
                UniAddress ud = UniAddress.GetByName(ip);
                NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(ip, username, password);
                SmbConstants.DefaultConnTimeout = timeOut * 1000;
                SmbConstants.DefaultResponseTimeout = timeOut * 1000;
                SmbConstants.DefaultSoTimeout = timeOut * 1000;
                SmbSession.Logon(ud, port, auth);//验证是否能够成功登录
                server.isSuccess = true;


            }
            catch (SmbAuthException fe)
            {
                server.isSuccess = false;
            }
            catch (Exception e)
            {
                if (e.Message.IndexOf("Failed to connect") != -1)
                {
                    throw new TimeoutException(e.Message);
                }
                else
                {
                    throw e;
                }

            }
            return server;
        }

    }
}
