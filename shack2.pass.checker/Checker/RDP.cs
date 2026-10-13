using System;
using RdpVerify;
using Tools;

namespace SNETCracker.Checker
{
    /// <summary>
    /// RDP 弱口令检测（基于 RdpVerify.Lib：NLA/CredSSP/NTLMv2 + 传统 RDP 安全层自动协商）。
    /// 账号密码验证在服务端完成，仅用于授权环境下的内部弱口令审计。
    /// </summary>
    class RDP : CheckerBase
    {
        public RDP()
        {

        }

        public override Server Crack(string ip, int port, string username, string password, int timeOut)
        {
            Server server = new Server();
            try
            {
                var result = RdpVerifier.CheckAsync(
                    ip, port, username, password, domain: "",
                    connectTimeoutMs: timeOut * 1000,
                    judgeWaitMs: 0) // 0 = 自动：NLA 3s / 传统安全层 15s
                    .GetAwaiter().GetResult();

                // Valid：凭据正确；Disabled：密码正确但账户被策略限制，同样说明口令命中
                server.isSuccess = result.Status == CheckStatus.Valid
                                || result.Status == CheckStatus.Disabled;
                server.banner = result.Detail;
            }
            catch (Exception e)
            {
                // 网络/协议异常：保持失败并记录到日志，不向上抛出打断任务队列
                server.isSuccess = false;
                server.banner = "RDP验证异常：" + e.Message;
                FileTool.log("RDP检查异常 " + ip + ":" + port + " " + e.Message + e.StackTrace);
            }
            return server;
        }
    }
}
