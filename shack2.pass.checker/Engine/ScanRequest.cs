using System.Collections.Generic;

namespace SNETCracker.Engine
{
    /// <summary>待检测服务：服务名 + 端口列表（端口来自 config/service.ini 或 CLI 指定）。</summary>
    public sealed class ScanService
    {
        public readonly string ServiceName;
        /// <summary>端口列表（CLI 显式 ip:port 端口覆盖时会改写，故不设 readonly）</summary>
        public int[] Ports;

        public ScanService(string serviceName, int[] ports)
        {
            ServiceName = serviceName;
            Ports = ports;
        }
    }

    /// <summary>一次扫描请求的输入：目标 + 服务 + 字典。字典按 AutoDic 语义二选一。</summary>
    public sealed class ScanRequest
    {
        /// <summary>已解析的目标列表（IP / 域名），由 TargetParser 产出</summary>
        public List<string> Targets = new List<string>();

        /// <summary>勾选的服务（含端口）</summary>
        public List<ScanService> Services = new List<ScanService>();

        /// <summary>AutoDic=true 时按服务名取字典（config/dic 目录加载结果）</summary>
        public Dictionary<string, HashSet<string>> ServiceUsernames = new Dictionary<string, HashSet<string>>();
        public Dictionary<string, HashSet<string>> ServicePasswords = new Dictionary<string, HashSet<string>>();

        /// <summary>AutoDic=false 时的全局用户名/密码集合</summary>
        public HashSet<string> Usernames = new HashSet<string>();
        public HashSet<string> Passwords = new HashSet<string>();
    }

    /// <summary>扫描参数。</summary>
    public sealed class ScanOptions
    {
        /// <summary>认证并发线程数（默认 30）</summary>
        public int Threads = 30;
        /// <summary>单次认证超时秒（默认 15）</summary>
        public int TimeoutSec = 15;
        /// <summary>网络/协议异常重试次数（默认 0）</summary>
        public int RetryCount = 0;
        /// <summary>是否先做端口开放探测（默认 true）</summary>
        public bool PortScan = true;
        /// <summary>是否按服务自动选择字典（默认 true）</summary>
        public bool AutoDic = true;
        /// <summary>账号后缀（如 @test.com）</summary>
        public string UsernameExt = "";
        /// <summary>文件日志目录（端口探测/成功结果落盘）；null 或空则不写文件</summary>
        public string LogDir = null;

        /// <summary>成功破解任意一个账号后停止所有剩余任务（默认 false）</summary>
        public bool StopOnSuccess = false;

        /// <summary>连接复用批次的密码分片数（默认 1=不分片）。
        /// 单目标大字典时 >1 可把同一目标的密码段切到多个并行连接上跑；
        /// 注意每片一条连接，分片过多可能更快触发服务端 MaxAuthTries/防爆破限制</summary>
        public int ReuseShardCount = 1;

        /// <summary>防账号锁定熔断：同一账号连续失败达此阈值跳过剩余密码（默认 50；
        /// 域控/生产库等严格环境建议调小到 5~10）</summary>
        public int LockoutFailLimit = 50;

        /// <summary>死主机短路（默认 true）：端口探测中某主机连续纯超时达 HostTimeoutLimit 次
        /// （RST 拒绝/端口开放会重置计数，说明主机存活），判定主机不存活并跳过其剩余端口探测。
        /// 大网段扫描提速数倍；代价是全端口被防火墙过滤的活主机会漏判</summary>
        public bool HostFailFast = true;
        /// <summary>死主机判定的连续纯超时次数（默认 5）</summary>
        public int HostTimeoutLimit = 5;

        /// <summary>单主机认证并发上限（默认 0 = 不限）。小目标数大并发场景防止全部线程
        /// 压同一台机器触发服务端防爆破/MaxAuthTries；批次任务整批占一个主机名额</summary>
        public int PerHostLimit = 0;
    }
}
