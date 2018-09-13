using LumiSoft.Net.AUTH;
using LumiSoft.Net.SMTP.Client;
using System;
using Tools;

namespace SNETCracker.Model
{
    class CrackSMTP: CrackService
    {
        public CrackSMTP()
        {

        }
        public override Server creack(String ip, int port,String username,String password,int timeOut) {
                SMTP_Client conn = null;
            Server server = new Server();
                try
                {
                    conn = new SMTP_Client();
                    conn.Timeout = timeOut;
                    conn.Connect(ip, port, false);
                    if (conn.IsConnected) {
                        conn.EhloHelo(ip);
                        AUTH_SASL_Client_Plain authInfo = new AUTH_SASL_Client_Plain(username, password);
                        conn.Auth(authInfo);
                        if (conn.IsAuthenticated)
                        {
                            server.isSuccess = conn.IsAuthenticated;
                            server.banner = conn.GreetingText;
                        }
                    }
                   
                }
                catch (Exception e)
                {
                    throw e;
                }
                finally
                {
                    if (conn != null)
                    {
                        conn.Disconnect();
                    }
                }
            return server;
        }
    }
}
