using System;
using VncSharp;

namespace SNETCracker.Model
{
    class CrackVNC: CrackService
    {
        public CrackVNC()
        {

        }
        public override Server creack(String ip, int port,String username,String password,int timeOut) {
            
            VncClient vc = null;
            Server server = new Server();
            try
            {
                vc = new VncClient();

                Boolean result = vc.Connect(ip, 0, port);
                if (result)
                {
                    server.isSuccess = vc.Authenticate(password);
                }
            }
            catch (Exception e)
            {
                throw e;
            }
            finally {
                if (vc != null) {
                    vc.Disconnect();
                }
            }
            return server;
        }
    }
}
