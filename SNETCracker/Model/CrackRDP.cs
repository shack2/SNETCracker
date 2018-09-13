using System;
namespace SNETCracker.Model
{
    class CrackRDP : CrackService
    {

        public CrackRDP()
        {

        }
        public override Server creack(String ip, int port, String username, String password, int timeOut) {
           
            return new Server();
        }

    }
}
