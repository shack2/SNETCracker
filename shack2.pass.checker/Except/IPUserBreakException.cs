using System;

namespace SNETCracker.Except
{
    class IPUserBreakException : Exception
    {
        public IPUserBreakException(string message) : base(message) { }

        public override string Message
        {
            get
            {
                return base.Message;
            }
        }
    }
}
