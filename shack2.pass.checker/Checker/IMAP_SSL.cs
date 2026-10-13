using System;

namespace SNETCracker.Checker
{
    /// <summary>IMAP（隐式 SSL）弱口令检测：协议逻辑与 IMAP 相同，仅传输层套 TLS。</summary>
    class IMAP_SSL : IMAP
    {
        public IMAP_SSL() : base(true)
        {
        }
    }
}
