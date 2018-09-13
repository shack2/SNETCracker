using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyRDP
{
    public enum ResponseType
    {
        Connecting,
        LoggedIn,
        LoginFailed,
        TimedOut,
        Connected,
        Disconnected,
        Finished,
        Error
    }
}