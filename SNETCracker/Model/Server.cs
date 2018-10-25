using MyRDP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace SNETCracker.Model
{
    public class Server
    {
        public bool isSuccess = false;
        public string banner = "";
        public string ip = "";
        public string serverName = "";
        public int port = 0;
        public string username = "";
        public string password = "";
        public Boolean isDisConnected = false;
        public int timeout = 10;
        public AutoResetEvent isEndMRE = new AutoResetEvent(false);
        public Boolean isConnected = false;
        public RdpClient client = null;
        public long userTime = 0;
    }
}
