using System;
using System.Collections.Generic;
using Tools;

namespace SNETCracker.Checker
{
    /// <summary>单次认证结果：成功 / 口令错误 / 连接失效需重连。</summary>
    internal enum AuthResult { Success, Failed, Closed }

    /// <summary>
    /// 扇出认证：无连接/无状态协议（SNMP/HTTP 系）可在一个超时窗口内并发尝试多个口令，
    /// 替代 IReusableAuth 的串行逐口令模式，字典越大提速越明显。
    /// </summary>
    internal interface IFanOutAuth : IDisposable
    {
        /// <summary>建立探测上下文（如 UDP socket / keep-alive 连接）。</summary>
        void Connect(string ip, int port, int timeoutSec);

        /// <summary>服务端标识（版本横幅等），用于结果展示。</summary>
        string Banner { get; }

        /// <summary>
        /// 一个窗口内并发尝试多个口令（user 固定），返回拿到确定结果的口令 → 结果；
        /// 窗口内无应答的口令不放入字典（调用方按口令错误处理：SNMP 错误 community 即无应答）。
        /// </summary>
        Dictionary<string, AuthResult> TryAuthMany(string user, IReadOnlyList<string> passwords);
    }

    /// <summary>
    /// 可复用连接认证：握手一次后可在同一连接上连续多次尝试（服务端认证失败后保持连接）。
    /// 适用于 SSH / Redis / FTP / SMTP / POP3 / IMAP / MongoDB 等；连接失效返回 Closed，由调度层重连。
    /// </summary>
    internal interface IReusableAuth : IDisposable
    {
        /// <summary>建立连接并完成协议握手。</summary>
        void Connect(string ip, int port, int timeoutSec);

        /// <summary>服务端标识（版本横幅等），用于结果展示。</summary>
        string Banner { get; }

        /// <summary>同一连接上执行一次认证。Success=口令正确；Failed=口令错误；Closed=连接失效需重连。</summary>
        AuthResult TryAuth(string user, string password);
    }

    public abstract class CheckerBase
    {
        public abstract Server Crack(String ip, int port, String username, String password, int timeOut);
    }
}
