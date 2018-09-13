using System;
using System.Diagnostics;
using System.Net;
using System.Threading;
using Tools;

namespace SNETCracker.Model
{
    class CrackTelnet : CrackService
    {
        public CrackTelnet() {

        }

        public override Server creack(String ip, int port,String username,String password,int timeOut) {
            TelnetClient tc = null;
            
            Server server = new Server();
            try
            {
                tc = new TelnetClient(ip, port);
                String s = tc.Login(username, password, timeOut * 1000);
                String prompt = s.TrimEnd();
                prompt = s.Substring(prompt.Length - 1, 1);
                server.banner = prompt;
                if (prompt != "$" && prompt != ">")
                {
                    return server;
                }
                
                if (tc.IsConnected)
                {
                    server.isSuccess = true; ;
                    
                }

            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                if (tc != null) {
                    tc.Dispose();
                }
            }
            return server;
        }
    }
}
