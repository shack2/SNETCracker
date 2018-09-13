using LumiSoft.Net.AUTH;
using LumiSoft.Net.POP3.Client;
using System;
using Tools;

namespace SNETCracker.Model
{
    class CrackPOP3 : CrackService
    {
        public CrackPOP3()
        {

        }
        public override Server creack(String ip, int port,String username,String password,int timeOut) {
                POP3_Client conn = null;
            Server server = new Server();
                try
                {
                    conn = new POP3_Client();
                    //与Pop3服务器建立连接
                    conn.Timeout = timeOut;
                    conn.Connect(ip, port, false);
                    if (conn.IsConnected)
                    {
                        conn.Login(username, password);
                        if (conn.IsAuthenticated)
                        {
                            server.isSuccess = conn.IsAuthenticated;
                            server.banner = conn.GreetingText;
                        }
                    } 
                }
                catch (Exception e) {
                    throw e;
                }
                finally
                {
                    if (conn != null&& conn.IsConnected)
                    {
                        conn.Disconnect();
                    }
                }
            return server;
        }
    }
}
