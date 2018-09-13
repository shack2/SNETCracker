using LumiSoft.Net.FTP.Client;
using System;
using System.Net;
using Tools;

namespace SNETCracker.Model
{
    class CrackFTP : CrackService
    {
        public CrackFTP() {

        }

        public override Server creack(String ip, int port,String username,String password,int timeOut) {
               
                FTP_Client ftp = null;
           
            Server server = new Server();
                try
                {
                    ftp = new FTP_Client();
                    ftp.Timeout = timeOut;
                    ftp.Connect(ip, port, false);
                    if (ftp.IsConnected)
                    {
                        ftp.Authenticate(username, password);
                        server.isSuccess = ftp.IsAuthenticated;
                        server.banner = ftp.GreetingText;
                    }
                }
                catch (Exception e)
                {
                    throw e;
                }
                finally {
                    if (ftp != null)
                    {
                        ftp.Disconnect();
                    }
                }
            return server;
        }
    }
}
