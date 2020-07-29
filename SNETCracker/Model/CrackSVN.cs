using System;

namespace SNETCracker.Model
{
    class CrackSVN : CrackService
    {
        public CrackSVN()
        {

        }
        public override Server creack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            return server;
        }
    }
}
