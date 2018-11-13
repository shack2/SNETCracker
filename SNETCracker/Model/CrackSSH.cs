using Chilkat;
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
            Rebex.Net.Ssh ssh = new Rebex.Net.Ssh();
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


        /*
       public override Server creack(string ip, int port, string username, string password, int timeOut)
       {
           Chilkat.Ssh ssh = new Chilkat.Ssh();
           
           Server server = new Server();
           try{
               bool success = ssh.UnlockComponent("blh6lp.SS10899_Oi30mPCYGbnd");
               if (success != true)
               {
                   throw new Exception("SSH组件解锁失败！");
               }


               success = ssh.Connect(ip, port);
               
               if (success != true)
               {
                   throw new Exception("SSH连接失败！");
               }
               else {
                    //  Wait a max of xx seconds when reading responses..
                  
                    ssh.IdleTimeoutMs = timeOut*1000;
                    ssh.ConnectTimeoutMs = timeOut * 1000;
                    ssh.ReadTimeoutMs= timeOut * 1000;
                    //Authenticate using login/password:
                    success = ssh.AuthenticatePw(username, password);
                    if (success == true)
                   {
                       server.isSuccess = true;
                   }
               }
           }catch (Exception e) {
               throw e;
           }
           finally {
               ssh.Disconnect();
           }
           return server;

       }*/

    }
}
