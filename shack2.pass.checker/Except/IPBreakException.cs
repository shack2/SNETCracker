using System;

namespace SNETCracker.Except
{
    class IPBreakException:Exception
    {
        public IPBreakException(string message) : base(message) { }

        public override string Message
        {
            get
            {
                return base.Message;
            }
        }
    }
}
