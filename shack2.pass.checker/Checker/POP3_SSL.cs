using System;

namespace SNETCracker.Checker
{
    /// <summary>
    /// POP3（隐式 SSL）弱口令检测：协议逻辑与 POP3 相同，传输层套 TLS。
    /// 注：旧 MailKit 实现误用非 SSL 连接（Connect 第三参为 false），本实现修正为真正的隐式 TLS。
    /// </summary>
    class POP3_SSL : POP3
    {
        public POP3_SSL() : base(true)
        {
        }
    }
}
