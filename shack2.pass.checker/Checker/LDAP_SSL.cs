using System;

namespace SNETCracker.Checker
{
    /// <summary>LDAPS（隐式 SSL，端口 636）弱口令检测：协议逻辑与 LDAP 相同，仅传输层套 TLS。</summary>
    class LDAP_SSL : LDAP
    {
        public LDAP_SSL() : base(true)
        {
        }
    }
}
