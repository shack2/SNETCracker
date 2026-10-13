using System;

namespace SNETCracker.Checker
{
    /// <summary>FTPS（隐式 SSL，端口 990）弱口令检测：协议逻辑与 FTP 相同，仅传输层套 TLS。</summary>
    class FTP_SSL : FTP
    {
        public FTP_SSL() : base(true)
        {
        }
    }
}
