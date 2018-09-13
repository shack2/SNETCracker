using Rebex.Net;
using System;
using Tools;

namespace SNETCracker.Model
{
    class CrackSSH: CrackService
    {
        public CrackSSH()
        {

        }

        public override Server creack(string ip, int port, string username, string password, int timeOut)
        {
            Ssh ssh = new Ssh();
            Server server = new Server();
            ssh.Timeout = timeOut * 1000;
            try
            {
                ssh.Connect(ip);
                if (ssh.IsConnected)
                {
                    ssh.Login(username, password);
                    if (ssh.IsAuthenticated)
                    {
                        server.isSuccess = true;
                        server.banner = ssh.ServerKey.Comment;
                    }
                }
            }
            catch (Exception e)
            {
                if (e.Message.IndexOf("incorrect") != -1)
                {
                    return server;
                }
                else {
                    throw e;
                }
            }
            finally
            {
                ssh.Disconnect();
            }
            return server;

        }


    }
}
