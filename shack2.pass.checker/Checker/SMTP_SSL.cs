using System;

namespace SNETCracker.Checker
{
    /// <summary>SMTP（隐式 SSL）弱口令检测：协议逻辑与 SMTP 相同，仅传输层套 TLS。</summary>
    class SMTP_SSL : SMTP
    {
        public SMTP_SSL() : base(true)
        {
        }
    }
}
