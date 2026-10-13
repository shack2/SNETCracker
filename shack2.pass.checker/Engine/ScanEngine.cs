using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SNETCracker.Checker;
using SNETCracker.Except;
using SPasswordCheckerV2.Data;
using Tools;

namespace SNETCracker.Engine
{
    /// <summary>
    /// 弱口令扫描引擎：端口探测 → 惰性枚举（用户×密码×目标）→ Parallel.ForEachAsync 限并发认证。
    /// 从 MainViewModel 抽出，UI 与 CLI 共用；UI 通过 Log/Found 回调接收日志和命中结果。
    /// 引擎为单实例单任务：每次 Run 前 Reset，同一实例不可并发 Run。
    /// </summary>
    public sealed class ScanEngine
    {
        /// <summary>运行日志回调（线程安全要求由调用方保证，回调可能在任意线程触发）</summary>
        public Action<string> LogHandler;
        /// <summary>命中成功结果回调</summary>
        public Action<CheckResult> FoundHandler;

        // ===================== 运行状态（进度展示 / 测试断言读取） =====================
        // 对外只读：内部用私有字段 + Interlocked 更新，公开属性仅暴露读快照，防止外部误写破坏计数
        /// <summary>服务名 → 存活 (ip, port) 队列（结构化存储，替代 "ip:port" 字符串反复切分）</summary>
        public ConcurrentDictionary<string, List<(string Ip, int Port)>> listCracker { get; private set; } = new ConcurrentDictionary<string, List<(string Ip, int Port)>>();
        /// <summary>端口探测剩余任务数</summary>
        private long _scanPortTaskSum = 0;
        public long scanPortTaskSum => Interlocked.Read(ref _scanPortTaskSum);
        /// <summary>端口探测总任务数</summary>
        private long _scanPortTaskTotal = 0;
        public long scanPortTaskTotal => Interlocked.Read(ref _scanPortTaskTotal);
        /// <summary>是否有存活服务（0/1）</summary>
        private int _isAlive = 0;
        public int isAlive => Volatile.Read(ref _isAlive);
        /// <summary>存活服务任务数</summary>
        private long _aliveTargetCount = 0;
        public long aliveTargetCount => Interlocked.Read(ref _aliveTargetCount);
        /// <summary>认证总任务数</summary>
        private long _checkSumCount = 0;
        public long checkSumCount => Interlocked.Read(ref _checkSumCount);
        /// <summary>已执行认证任务数</summary>
        private long _allCrackCount = 0;
        public long allCrackCount => Interlocked.Read(ref _allCrackCount);
        /// <summary>正在执行认证的活跃任务数</summary>
        private int _activeAuthCount = 0;
        public int activeAuthCount => Volatile.Read(ref _activeAuthCount);
        /// <summary>成功破解数</summary>
        private int _checkSuccessCount = 0;
        public int checkSuccessCount => Volatile.Read(ref _checkSuccessCount);

        // 判重/熔断状态
        private ConcurrentDictionary<string, byte> succeededKeys = new ConcurrentDictionary<string, byte>();
        private ConcurrentDictionary<string, byte> deadTargets = new ConcurrentDictionary<string, byte>();
        private ConcurrentDictionary<string, int> failStreaks = new ConcurrentDictionary<string, int>();
        // 死主机短路状态（HostFailFast）：连续纯超时计数 / 已判死主机
        private ConcurrentDictionary<string, int> hostTimeoutStreaks = new ConcurrentDictionary<string, int>();
        private ConcurrentDictionary<string, byte> deadHosts = new ConcurrentDictionary<string, byte>();
        // 单主机认证并发闸门（PerHostLimit>0 时启用）
        private ConcurrentDictionary<string, SemaphoreSlim> hostGates = new ConcurrentDictionary<string, SemaphoreSlim>();
        // 域名解析缓存：避免同一域名目标在探测/认证中反复 DNS 查询
        private readonly ConcurrentDictionary<string, System.Net.IPAddress> dnsCache = new ConcurrentDictionary<string, System.Net.IPAddress>();
        // 复用批次的密码快照（按服务共享一份只读列表，替代每批次 ToList 复制）
        private readonly ConcurrentDictionary<string, List<string>> passSnapshots = new ConcurrentDictionary<string, List<string>>();
        /// <summary>成功即停标志（0/1）：StopOnSuccess 开启时首个成功后置 1，各路径入口/循环检查并补齐进度</summary>
        private int stopAll = 0;
        private bool StopAll => Volatile.Read(ref stopAll) == 1;

        /// <summary>命中成功后的统一收尾：计数、判重、可选全局停止</summary>
        private void OnAuthSuccess(string key, string logAccount)
        {
            succeededKeys.TryAdd(key, 0);
            if (opt.StopOnSuccess && Interlocked.CompareExchange(ref stopAll, 1, 0) == 0)
            {
                Log("已成功破解账号 " + logAccount + "，按「成功一个账号停止」设置停止剩余所有任务！");
            }
        }

        /// <summary>认证成功的完整收尾（逐任务/复用批次/扇出三条路径共用）：
        /// 成功计数、判重、成功即停、结果回调、成功日志落盘</summary>
        private void HandleAuthSuccess(string key, string ip, int port, string serviceName,
            string username, string password, string banner, long useTime)
        {
            Interlocked.Increment(ref _checkSuccessCount);
            OnAuthSuccess(key, username + "@" + ip + ":" + port);
            string sinfo = ip + "---------" + username + "----" + password + "----" + banner + "----成功！";
            CheckResult cr = new CheckResult(_checkSuccessCount, ip, serviceName, port, username, password, banner, useTime);
            Found(cr);
            string okLog = LogFile("success");
            if (okLog != null)
            {
                FileTool.AppendLogToFile(okLog, sinfo);
            }
        }

        /// <summary>认证失败熔断计数：累计同一账号连续失败次数，返回当前连败数（三条路径共用）；
        /// 达阈值后的处置策略（跳过/停止该账号）由各路径按自身循环结构处理</summary>
        private int NoteAuthFail(string key)
        {
            return failStreaks.AddOrUpdate(key, 1, (_, c) => c + 1);
        }

        private ScanRequest req;
        private ScanOptions opt;

        private void Log(string msg) => LogHandler?.Invoke(msg);
        private void Found(CheckResult cr) => FoundHandler?.Invoke(cr);

        private string LogFile(string name)
        {
            return opt?.LogDir == null ? null : opt.LogDir + "/" + name + "-" + DateTime.Now.ToString("yyyy-MM-dd") + ".log";
        }

        /// <summary>重置本次任务状态（判重表/计数器），保证停止后可重新开始</summary>
        public void Reset()
        {
            listCracker = new ConcurrentDictionary<string, List<(string Ip, int Port)>>();
            succeededKeys = new ConcurrentDictionary<string, byte>();
            deadTargets = new ConcurrentDictionary<string, byte>();
            failStreaks = new ConcurrentDictionary<string, int>();
            hostTimeoutStreaks = new ConcurrentDictionary<string, int>();
            deadHosts = new ConcurrentDictionary<string, byte>();
            hostGates = new ConcurrentDictionary<string, SemaphoreSlim>();
            passSnapshots.Clear();
            stopAll = 0;
            _scanPortTaskSum = 0;
            _scanPortTaskTotal = 0;
            _isAlive = 0;
            _aliveTargetCount = 0;
            _checkSumCount = 0;
            _allCrackCount = 0;
            _activeAuthCount = 0;
            _checkSuccessCount = 0;
        }

        /// <summary>执行一轮扫描（同步阻塞；调用方自行 Task.Run）。停止用 CancellationToken。</summary>
        public void Run(ScanRequest request, ScanOptions options, CancellationToken ct)
        {
            req = request;
            opt = options;
            Reset();
            // 各检测器按目标缓存（Oracle 服务名、DB2 库名）与任务同生命周期
            CheckerRegistry.ClearAllTargetCaches();
            // 预热线程池：认证任务是阻塞 I/O，Parallel.ForEachAsync 用线程池线程执行，
            // 默认注入速度慢（约每秒 1 个），高并发设置下预热避免启动爬坡
            ThreadPool.GetMinThreads(out int minWorker, out int minIo);
            if (minWorker < opt.Threads + 4)
            {
                ThreadPool.SetMinThreads(opt.Threads + 4, minIo);
            }

            List<ScanService> selectedServices = req.Services;
            if (opt.PortScan)
            {
                GetSumTaskCount();
                int scanTimeoutSec = Math.Min(Math.Max(1, opt.TimeoutSec), 3);
                //端口探测是纯 I/O 等待：高并发异步连接，吞吐不再受认证线程数限制
                int scanConcurrency = Math.Max(500, opt.Threads * 10);
                Log("开始端口探测，共 " + _scanPortTaskSum + " 个探测任务（并发 " + scanConcurrency + "，单任务最长 " + scanTimeoutSec + " 秒）...");
                ScanPortsAsync(selectedServices, scanTimeoutSec * 1000, scanConcurrency, ct).GetAwaiter().GetResult();
                Log("验证端口开放完成!");
            }
            else
            {
                // 不预扫端口：所有目标×服务端口直接入队认证
                foreach (ScanService sv in selectedServices)
                {
                    List<(string Ip, int Port)> list = listCracker.GetOrAdd(sv.ServiceName, _ => new List<(string Ip, int Port)>());
                    foreach (string ip in req.Targets)
                    {
                        foreach (int port in sv.Ports)
                        {
                            list.Add((ip, port));
                            _aliveTargetCount++;
                        }
                    }
                }
                _isAlive = _aliveTargetCount > 0 ? 1 : 0;
            }

            if (_isAlive <= 0)
            {
                Log("未发现存活的服务，停止检查！");
                return;
            }
            Log("开始检查，共" + _aliveTargetCount + "个服务检查任务！");
            //计算检查总数（先转 long 再乘：大目标×大字典时三个 int 相乘会溢出成负数）
            foreach (var item in listCracker)
            {
                if (opt.AutoDic)
                {
                    _checkSumCount += (long)item.Value.Count * Math.Max(1, ServiceUsers(item.Key).Count) * ServicePasses(item.Key).Count;
                }
                else
                {
                    _checkSumCount += (long)item.Value.Count * Math.Max(1, req.Usernames.Count) * req.Passwords.Count;
                }
            }
            Log("计算总任务，共" + _checkSumCount + "个任务！");
            // 惰性枚举 + Parallel.ForEachAsync 限并发：任务流式拉取，
            // 不再把 用户×密码×目标 全量组合物化进内存（大字典防内存爆炸）
            var parOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Max(1, opt.Threads),
                CancellationToken = ct
            };
            Parallel.ForEachAsync(EnumerateCheckTasks(), parOptions, (item, token) =>
            {
                if (item is AuthBatch batch)
                {
                    RunReuseBatch(batch, token);
                }
                else
                {
                    crackerService((CheckTask)item, token);
                }
                return ValueTask.CompletedTask;
            }).GetAwaiter().GetResult();
        }

        /// <summary>按服务取用户名字典（AutoDic 路径），缺失服务回退空集合</summary>
        private HashSet<string> ServiceUsers(string serviceName)
        {
            return req.ServiceUsernames.TryGetValue(serviceName, out HashSet<string> s) ? s : new HashSet<string>();
        }

        private HashSet<string> ServicePasses(string serviceName)
        {
            return req.ServicePasswords.TryGetValue(serviceName, out HashSet<string> s) ? s : new HashSet<string>();
        }

        // ===================== 任务模型 =====================

        /// <summary>单个认证任务</summary>
        private sealed class CheckTask
        {
            public readonly string Ip;
            public readonly int Port;
            public readonly string ServiceName;
            public readonly string Username;
            public readonly string Password;

            public CheckTask(string ip, int port, string serviceName, string username, string password)
            {
                Ip = ip;
                Port = port;
                ServiceName = serviceName;
                Username = username;
                Password = password;
            }
        }

        /// <summary>连接复用批次任务：一个 ip:port 目标的所有 用户×密码 组合在同一连接上顺序尝试，
        /// 省去每个密码一次完整握手（服务端主动断开时自动重连续跑）</summary>
        private sealed class AuthBatch
        {
            public readonly string Ip;
            public readonly int Port;
            public readonly string ServiceName;
            /// <summary>密码分片起点（-1 = 全量字典，不分片）</summary>
            public readonly int PassOffset;
            /// <summary>密码分片长度（-1 = 全量字典，不分片）</summary>
            public readonly int PassCount;

            public AuthBatch(string ip, int port, string serviceName, int passOffset = -1, int passCount = -1)
            {
                Ip = ip;
                Port = port;
                ServiceName = serviceName;
                PassOffset = passOffset;
                PassCount = passCount;
            }
        }

        /// <summary>惰性枚举认证任务（用户×密码×目标流式产出，不物化全量组合）；
        /// 保持原有顺序：用户 → 密码 → 目标；空用户名字典补一个空串（让检测器走 IsNullOrEmpty 回退：Redis 单密码 AUTH、VNC 仅密码等）。
        /// 可复用协议（实现 IReusableAuth / IFanOutAuth）不逐密码产出，改为按目标产出
        /// AuthBatch（连接复用/扇出），是否可复用以接口为准，不再维护硬编码名单</summary>
        private IEnumerable<object> EnumerateCheckTasks()
        {
            foreach (var item in listCracker)
            {
                string serviceName = item.Key;
                HashSet<string> users = opt.AutoDic ? ServiceUsers(serviceName) : req.Usernames;
                HashSet<string> passes = opt.AutoDic ? ServicePasses(serviceName) : req.Passwords;
                if (users.Count <= 0)
                {
                    users = new HashSet<string> { "" };
                }
                List<(string Ip, int Port)> targets;
                lock (item.Value)
                {
                    targets = item.Value.ToList(); // 快照，与扫描入队解耦
                }
                bool reusable = CheckerRegistry.TryCreate(serviceName, out CheckerBase probe)
                    && (probe is IReusableAuth || probe is IFanOutAuth);
                if (reusable)
                {
                    // 密码分片：ReuseShardCount>1 时把字典切成多段，每段一个批次（独立连接并行跑），
                    // 解决单目标大字典退化为单连接串行的问题
                    int passCount = passes.Count;
                    int shards = passCount > 0 ? Math.Min(Math.Max(1, opt.ReuseShardCount), passCount) : 1;
                    int perShard = (passCount + shards - 1) / shards;
                    foreach ((string ip, int port) in targets)
                    {
                        for (int s = 0; s < shards; s++)
                        {
                            int off = s * perShard;
                            int cnt = Math.Min(perShard, passCount - off);
                            if (cnt <= 0) break;
                            yield return new AuthBatch(ip, port, serviceName, shards > 1 ? off : -1, shards > 1 ? cnt : -1);
                        }
                    }
                    continue;
                }
                foreach (string user in users)
                {
                    string username = user + opt.UsernameExt;
                    foreach (string pass in passes)
                    {
                        //替换变量密码（"空"/%user% 统一处理）
                        string npass = CredentialExpander.Expand(user, pass);
                        foreach ((string ip, int port) in targets)
                        {
                            yield return new CheckTask(ip, port, serviceName, username, npass);
                        }
                    }
                }
            }
        }

        // ===================== 端口探测 =====================

        private void GetSumTaskCount()
        {
            foreach (ScanService sv in req.Services)
            {
                _scanPortTaskSum += (long)req.Targets.Count * sv.Ports.Length;
            }
            _scanPortTaskTotal = _scanPortTaskSum;
        }

        /// <summary>同步端口探测（供测试/单点调用）；批量扫描走 ScanPortsAsync</summary>
        public void ScanPort(string ip, string serviceName, int port, int timeoutSec)
        {
            try
            {
                using (TcpClient tc = new TcpClient())
                {
                    IAsyncResult oAsyncResult = tc.BeginConnect(ip, port, null, null);
                    //端口探测用较短超时（最长 3 秒）：不存活的主机只能等满超时，用认证超时（默认 15 秒）会让大网段扫描极慢
                    //AsyncWaitHandle 是内核句柄，必须释放，否则大网段探测会累积句柄泄漏
                    using (oAsyncResult.AsyncWaitHandle)
                    {
                        oAsyncResult.AsyncWaitHandle.WaitOne(Math.Min(Math.Max(1, timeoutSec), 3) * 1000, true);
                    }
                    if (tc.Connected)
                    {
                        RegisterOpenPort(ip, serviceName, port);
                    }
                }
            }
            catch (SocketException e)
            {
                Log(ip + " port " + port + " 关闭！" + e.Message);
            }
            Interlocked.Decrement(ref _scanPortTaskSum);
        }

        /// <summary>高并发异步端口扫描：探测是纯 I/O 等待，用数百并发连接替代线程池排队，大网段扫描提速一个数量级；
        /// 惰性枚举探测项（Parallel.ForEachAsync 流式拉取），不预建全部 Task 对象</summary>
        private async Task ScanPortsAsync(List<ScanService> selectedServices, int timeoutMs, int maxConcurrency, CancellationToken ct)
        {
            var items = from sv in selectedServices
                        from port in sv.Ports
                        from ip in req.Targets
                        select (ip, sv.ServiceName, port);
            var options = new ParallelOptions { MaxDegreeOfParallelism = maxConcurrency, CancellationToken = ct };
            await Parallel.ForEachAsync(items, options, async (t, _) =>
            {
                await ProbePortAsync(t.ip, t.ServiceName, t.port, timeoutMs, ct);
            });
        }

        /// <summary>UDP 协议服务集合：这些服务的存活探测走 UDP 发包而非 TCP 连接</summary>
        private static readonly HashSet<string> UdpServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "SNMP" };

        /// <summary>SNMP v2c GetRequest(sysDescr.0, community=public) 探测包，用于 UDP 端口存活探测</summary>
        private static readonly byte[] SnmpProbePacket =
        {
            0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
            0xa0, 0x1c, 0x02, 0x04, 0x6d, 0x0f, 0x5a, 0x3c, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00
        };

        /// <summary>域名解析缓存：IP 直返，域名解析一次后复用（避免每端口/每认证重复 DNS 查询）</summary>
        private System.Net.IPAddress ResolveCached(string host)
        {
            if (System.Net.IPAddress.TryParse(host, out System.Net.IPAddress parsed))
            {
                return parsed;
            }
            return dnsCache.GetOrAdd(host, h => System.Net.Dns.GetHostAddresses(h)[0]);
        }

        /// <summary>主机存活信号（端口开放或收到 RST 拒绝）：重置其连续超时计数</summary>
        private void NoteHostAlive(string ip)
        {
            if (opt.HostFailFast)
            {
                hostTimeoutStreaks.TryRemove(ip, out _);
            }
        }

        /// <summary>纯超时信号：累计连续超时次数，达阈值判定死主机并跳过其剩余端口探测</summary>
        private void NoteHostTimeout(string ip)
        {
            if (!opt.HostFailFast)
            {
                return;
            }
            int streak = hostTimeoutStreaks.AddOrUpdate(ip, 1, (_, c) => c + 1);
            if (streak >= Math.Max(1, opt.HostTimeoutLimit) && deadHosts.TryAdd(ip, 0))
            {
                Log("主机 " + ip + " 连续 " + streak + " 次探测超时，判定不存活，跳过其剩余端口探测");
            }
        }

        private async Task ProbePortAsync(string ip, string serviceName, int port, int timeoutMs, CancellationToken ct)
        {
            if (UdpServices.Contains(serviceName))
            {
                await ProbeUdpPortAsync(ip, serviceName, port, timeoutMs, ct);
                return;
            }
            try
            {
                // 死主机短路：已判死不存活的主机直接跳过（finally 照常递减任务计数）
                if (deadHosts.ContainsKey(ip))
                {
                    return;
                }
                using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                using (var tc = new TcpClient())
                {
                    cts.CancelAfter(timeoutMs);
                    await tc.ConnectAsync(ResolveCached(ip), port, cts.Token);
                    RegisterOpenPort(ip, serviceName, port);
                    NoteHostAlive(ip);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw; // 用户停止：向外抛出让扫描终止
            }
            catch (OperationCanceledException)
            {
                // 探测超时：唯一不计主机存活信号的结果（RST 拒绝说明主机活着）
                NoteHostTimeout(ip);
            }
            catch (SocketException)
            {
                // 拒绝连接（RST）：端口不开放，但主机存活
                NoteHostAlive(ip);
            }
            catch (ObjectDisposedException)
            {
                // 超时取消与连接完成的竞争导致的释放异常，视为不开放（不计主机死活）
            }
            finally
            {
                Interlocked.Decrement(ref _scanPortTaskSum);
            }
        }

        /// <summary>UDP 端口探测（SNMP）：发 GetRequest，有响应即判开放；关闭端口会收到 ICMP 端口不可达。
        /// UDP 无重传机制，单次丢包会误判不存活：超时后间隔 200ms 再发一次，两轮都超时才判不开放</summary>
        private async Task ProbeUdpPortAsync(string ip, string serviceName, int port, int timeoutMs, CancellationToken ct)
        {
            try
            {
                using (var udp = new UdpClient())
                {
                    System.Net.IPAddress addr = ResolveCached(ip);
                    for (int attempt = 0; attempt < 2; attempt++)
                    {
                        try
                        {
                            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                            {
                                cts.CancelAfter(timeoutMs);
                                await udp.SendAsync(SnmpProbePacket, SnmpProbePacket.Length, new System.Net.IPEndPoint(addr, port));
                                UdpReceiveResult result = await udp.ReceiveAsync(cts.Token);
                                if (result.Buffer.Length > 0)
                                {
                                    RegisterOpenPort(ip, serviceName, port);
                                }
                                return; // 有应答（无论是否判开放）即结束
                            }
                        }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested)
                        {
                            throw; // 用户停止：向外抛出让扫描终止
                        }
                        catch (OperationCanceledException)
                        {
                            // 本轮超时：还有重发机会则间隔 200ms 再试
                            if (attempt == 0)
                            {
                                await Task.Delay(200, ct);
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (SocketException)
            {
                // ICMP 端口不可达等，端口不开放
            }
            catch (ObjectDisposedException)
            {
                // 超时竞争，视为不开放
            }
        }

        /// <summary>登记开放端口：入队待破解、计数、写日志（线程安全，同步/异步两条路径共用）</summary>
        private void RegisterOpenPort(string ip, string serviceName, int port)
        {
            List<(string Ip, int Port)> list = listCracker.GetOrAdd(serviceName, _ => new List<(string Ip, int Port)>());
            lock (list)
            {
                list.Add((ip, port));
            }
            //有存活
            _isAlive = 1;
            Interlocked.Increment(ref _aliveTargetCount);
            Log(ip + " port " + port + " 开放！");
            // 走缓冲批量落盘：大网段扫出大量存活端口时避免每次开关文件+全局锁
            string scanLog = LogFile("portscan");
            if (scanLog != null)
            {
                FileTool.logToFile(scanLog, ip + ":" + port + ":" + serviceName);
            }
        }

        // ===================== 认证执行 =====================

        /// <summary>P1-6 检测器线程本地缓存：逐任务模式下每个认证任务都 new 一个检测器实例，
        /// 改为线程内按服务名缓存复用。安全性依据：走逐任务路径的都是非复用检测器（连接在 Crack 内
        /// 以 using 建立/释放），检测器类无跨任务实例字段（唯一例外 Kafka.correlationId 每次 Crack 开头重置）</summary>
        [ThreadStatic]
        private static Dictionary<string, CheckerBase> tlsCheckers;

        private static CheckerBase GetThreadChecker(string serviceName)
        {
            Dictionary<string, CheckerBase> cache = tlsCheckers;
            if (cache == null)
            {
                cache = new Dictionary<string, CheckerBase>(StringComparer.OrdinalIgnoreCase);
                tlsCheckers = cache;
            }
            if (!cache.TryGetValue(serviceName, out CheckerBase cb))
            {
                if (!CheckerRegistry.TryCreate(serviceName, out cb))
                {
                    return null;
                }
                cache[serviceName] = cb;
            }
            return cb;
        }

        /// <summary>取单主机并发闸门（PerHostLimit>0 时按主机创建信号量，否则返回 null 不限流）</summary>
        private SemaphoreSlim HostGate(string ip)
        {
            return opt.PerHostLimit > 0
                ? hostGates.GetOrAdd(ip, _ => new SemaphoreSlim(opt.PerHostLimit))
                : null;
        }

        private void crackerService(CheckTask task, CancellationToken ct)
        {
            Interlocked.Increment(ref _activeAuthCount);
            SemaphoreSlim gate = null;
            bool acquired = false;
            try
            {
                // 同一账号已成功则跳过剩余密码尝试（O(1) 查表，替代原结果表线性扫描）；
                // 注意：只按成功跳过，不能按"已尝试"跳过，否则每个账号只会试第一个密码
                string key = task.Ip + ":" + task.Port + ":" + task.ServiceName + ":" + task.Username;
                if (succeededKeys.ContainsKey(key))
                {
                    return;
                }
                // 目标已被服务端拉黑/拒绝本机接入：剩余尝试必然失败，直接跳过（进度计数在 finally 照常 +1）
                if (deadTargets.ContainsKey(task.Ip + ":" + task.Port))
                {
                    return;
                }
                // 成功即停：已有账号破解成功，剩余任务全部跳过
                if (StopAll)
                {
                    return;
                }
                // A7 防账号锁定熔断：同一账号连续失败达阈值，跳过其剩余密码
                if (failStreaks.TryGetValue(key, out int fuseStreak) && fuseStreak >= opt.LockoutFailLimit)
                {
                    return;
                }

                // 单主机并发限流：排队等主机名额，防止全部线程压同一台机器触发防爆破
                gate = HostGate(task.Ip);
                if (gate != null)
                {
                    gate.Wait(ct);
                    acquired = true;
                }

                Server server = new Server();
                // 认证给出确定结果（成功/失败）即停止；仅在网络/协议异常时按重试次数重试
                for (int attempt = 0; attempt <= opt.RetryCount; attempt++)
                {
                    System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
                    try
                    {
                        // 静态注册表分发（Native AOT 兼容；替代 Type.GetType + Activator 反射）
                        // 经线程本地缓存取实例，避免每任务一次分配
                        CheckerBase cs = GetThreadChecker(task.ServiceName);
                        if (cs != null)
                        {
                            server = cs.Crack(task.Ip, task.Port, task.Username, task.Password, opt.TimeoutSec);
                        }
                    }
                    catch (IPBreakException)
                    {
                        // 服务端明确拒绝本机接入（如 MySQL 未授权此 IP）：拉黑目标，不重试，
                        // 该目标后续任务在入口处批量跳过
                        if (deadTargets.TryAdd(task.Ip + ":" + task.Port, 0))
                        {
                            Log("目标 " + task.Ip + ":" + task.Port + " 不允许本机连接（未开远程访问或被拉黑），已跳过其剩余所有尝试");
                        }
                        sw.Stop();
                        server.userTime = sw.ElapsedMilliseconds;
                        break;
                    }
                    catch (Exception e)
                    {
                        string logInfo = "检查" + task.Ip + ":" + task.Port + " 登录发生异常！" + e.Message;
                        Log(logInfo);
                        FileTool.log(logInfo + e.StackTrace);
                        sw.Stop();
                        server.userTime = sw.ElapsedMilliseconds;
                        continue; // 只有异常才进入下一次重试
                    }
                    sw.Stop();
                    server.userTime = sw.ElapsedMilliseconds;
                    break;
                }
                if (server.isSuccess)
                {
                    HandleAuthSuccess(key, task.Ip, task.Port, task.ServiceName, task.Username, task.Password, server.banner, server.userTime);
                }
                else
                {
                    // A7 防账号锁定熔断：累计同一账号连续失败次数，达阈值记录一次日志
                    int streak = NoteAuthFail(key);
                    if (streak == opt.LockoutFailLimit)
                    {
                        Log("目标 " + task.Ip + ":" + task.Port + " 账号 " + task.Username
                            + " 连续失败 " + streak + " 次，为防触发账号锁定策略，已跳过该账号剩余密码");
                    }
                }
            }
            catch (Exception e)
            {
                Log(e.Message + e.StackTrace);
            }
            finally
            {
                if (acquired)
                {
                    gate.Release();
                }
                Interlocked.Decrement(ref _activeAuthCount);
                Interlocked.Increment(ref _allCrackCount);
            }
        }

        /// <summary>可复用连接批次执行：同一连接上顺序尝试 用户×密码，省去每个密码一次完整握手
        /// （适用于 SSH/Redis/FTP/SMTP/POP3/IMAP/MongoDB/LDAP/HTTP 系等认证失败后连接保持的协议）；
        /// 服务端主动断开（如 MaxAuthTries）时自动重连续跑（当前密码结果未知，重连后重试，不计进度）；
        /// 连接反复失败超过重试次数则放弃该目标，剩余组合一次性补齐进度</summary>
        private void RunReuseBatch(AuthBatch batch, CancellationToken ct)
        {
            HashSet<string> users = opt.AutoDic ? ServiceUsers(batch.ServiceName) : req.Usernames;
            HashSet<string> passes = opt.AutoDic ? ServicePasses(batch.ServiceName) : req.Passwords;
            if (users.Count <= 0)
            {
                users = new HashSet<string> { "" };
            }
            // 密码快照按服务共享一份（AutoDic 每服务一份，全局模式共用一份），不再每批次 ToList 复制；
            // 大目标×大字典场景避免 目标数×字典长 的列表分配 churn
            string snapKey = opt.AutoDic ? batch.ServiceName : "*";
            List<string> passSnapshot = passSnapshots.GetOrAdd(snapKey, _ => passes.ToList());
            // 密码分片：本批次只跑自己负责的字典段（复用批次并行化，分片产出见 EnumerateCheckTasks）；
            // 用起始下标+长度圈定区间，不切片复制
            int passStart = batch.PassOffset >= 0 ? Math.Min(batch.PassOffset, passSnapshot.Count) : 0;
            int passTotal = batch.PassOffset >= 0
                ? Math.Max(0, Math.Min(batch.PassCount, passSnapshot.Count - passStart))
                : passSnapshot.Count;

            // 扇出协议（SNMP 等无连接协议）：整段密码一个超时窗口内并发判定，走独立路径
            if (CheckerRegistry.TryCreate(batch.ServiceName, out CheckerBase probe)
                && probe is IFanOutAuth)
            {
                RunFanOutBatch(batch, users, passSnapshot, passStart, passTotal, ct);
                return;
            }

            Interlocked.Increment(ref _activeAuthCount);
            SemaphoreSlim gate = HostGate(batch.Ip);
            bool acquired = false;
            IReusableAuth conn = null;
            try
            {
                // 单主机并发限流：整批占一个主机名额（批次内是单连接串行尝试）
                if (gate != null)
                {
                    gate.Wait(ct);
                    acquired = true;
                }
                long targetTotal = (long)users.Count * passTotal;
                long done = 0; // 已计入进度（已尝试或已跳过）的组合数
                bool abandoned = deadTargets.ContainsKey(batch.Ip + ":" + batch.Port);
                int reconnects = 0; // 握手/协议连续失败次数（受 RetryCount 限制，拿到确定认证结果即清零）
                int stalled = 0;    // 连续零进展连接数（一连接就被踢的异常场景兜底，正常断连重连不计）
                bool progressThisConn = false; // 当前连接是否已拿到过确定认证结果

                foreach (string user in users)
                {
                    if (abandoned)
                    {
                        break;
                    }
                    // 成功即停：已有账号破解成功，本批次剩余组合计入进度补齐
                    if (StopAll)
                    {
                        abandoned = true;
                        break;
                    }
                    ct.ThrowIfCancellationRequested();
                    string username = user + opt.UsernameExt;
                    string key = batch.Ip + ":" + batch.Port + ":" + batch.ServiceName + ":" + username;
                    if (succeededKeys.ContainsKey(key))
                    {
                        done += passTotal; // 该账号已成功过：剩余密码整段跳过
                        continue;
                    }
                    int pi = 0;
                    bool stopUser = false;
                    while (pi < passTotal && !stopUser && !abandoned && !StopAll)
                    {
                        ct.ThrowIfCancellationRequested();
                        string npass = CredentialExpander.Expand(user, passSnapshot[passStart + pi]);
                        AuthResult r;
                        try
                        {
                            if (conn == null)
                            {
                                if (!CheckerRegistry.TryCreate(batch.ServiceName, out CheckerBase cb)
                                    || !(cb is IReusableAuth ra))
                                {
                                    throw new Exception("服务 " + batch.ServiceName + " 不支持连接复用");
                                }
                                conn = ra;
                                conn.Connect(batch.Ip, batch.Port, opt.TimeoutSec);
                                progressThisConn = false;
                            }
                            r = conn.TryAuth(username, npass);
                        }
                        catch (Exception e)
                        {
                            // 握手失败/协议异常：连接作废，重连重试当前密码（不计进度）
                            try { conn?.Dispose(); } catch { }
                            conn = null;
                            if (++reconnects > opt.RetryCount)
                            {
                                Log("检查" + batch.Ip + ":" + batch.Port + " 连接反复失败，放弃该目标！" + e.Message);
                                FileTool.log(batch.ServiceName + "批次放弃 " + batch.Ip + ":" + batch.Port + " " + e.Message + e.StackTrace);
                                abandoned = true;
                            }
                            continue;
                        }
                        if (r == AuthResult.Closed)
                        {
                            // 服务端主动断开（如 MaxAuthTries）：当前密码结果未知，重连后重试。
                            // 这是复用模式的正常路径，不受 RetryCount 限制；仅当连续几个连接都零进展
                            // （一连接就被踢）时才放弃，防止异常服务端导致死循环
                            try { conn?.Dispose(); } catch { }
                            conn = null;
                            if (!progressThisConn && ++stalled > 3)
                            {
                                Log("检查" + batch.Ip + ":" + batch.Port + " 连接被服务端反复断开，放弃该目标！");
                                abandoned = true;
                            }
                            continue;
                        }
                        reconnects = 0; // 拿到确定结果（成功/口令错误）
                        stalled = 0;
                        progressThisConn = true;
                        done++;
                        pi++;
                        Interlocked.Increment(ref _allCrackCount);
                        if (r == AuthResult.Success)
                        {
                            HandleAuthSuccess(key, batch.Ip, batch.Port, batch.ServiceName, username, npass, conn.Banner, 0);
                            stopUser = true; // 该账号成功：剩余密码跳过
                        }
                        else if (r == AuthResult.Failed)
                        {
                            // A7 防账号锁定熔断：同一账号连续失败达阈值，跳过其剩余密码
                            int streak = NoteAuthFail(key);
                            if (streak >= opt.LockoutFailLimit)
                            {
                                Log("目标 " + batch.Ip + ":" + batch.Port + " 账号 " + username
                                    + " 连续失败 " + streak + " 次，为防触发账号锁定策略，已跳过该账号剩余密码");
                                failStreaks.TryRemove(key, out _);
                                stopUser = true;
                            }
                        }
                    }
                    if (stopUser)
                    {
                        done += passTotal - pi; // 成功短路/锁定熔断的剩余密码计入进度
                    }
                }
                long skipped = targetTotal - done;
                if (skipped > 0)
                {
                    // 账号成功短路/目标放弃未跑到的组合一次性计入进度，保证进度条能到 100%
                    Interlocked.Add(ref _allCrackCount, skipped);
                }
            }
            catch (OperationCanceledException)
            {
                throw; // 停止指令：未尝试的任务不计进度（与逐任务模式一致）
            }
            catch (Exception e)
            {
                Log(e.Message + e.StackTrace);
            }
            finally
            {
                try { conn?.Dispose(); } catch { }
                if (acquired)
                {
                    gate.Release();
                }
                Interlocked.Decrement(ref _activeAuthCount);
            }
        }

        /// <summary>扇出批次执行（IFanOutAuth）：密码按块扇出，一个超时窗口内并发判定整段口令
        /// （SNMP 等无连接协议，错误口令=无应答）。整窗零应答视为目标不可达，重连重试。</summary>
        private void RunFanOutBatch(AuthBatch batch, HashSet<string> users, List<string> passSnapshot, int passStart, int passTotal, CancellationToken ct)
        {
            Interlocked.Increment(ref _activeAuthCount);
            SemaphoreSlim gate = HostGate(batch.Ip);
            bool acquired = false;
            IFanOutAuth fan = null;
            long targetTotal = (long)users.Count * passTotal;
            long done = 0;
            bool abandoned = deadTargets.ContainsKey(batch.Ip + ":" + batch.Port);
            int reconnects = 0;
            try
            {
                if (gate != null)
                {
                    gate.Wait(ct);
                    acquired = true;
                }
                foreach (string user in users)
                {
                    if (abandoned)
                    {
                        break;
                    }
                    // 成功即停：已有账号破解成功，本批次剩余组合计入进度补齐
                    if (StopAll)
                    {
                        abandoned = true;
                        break;
                    }
                    ct.ThrowIfCancellationRequested();
                    string username = user + opt.UsernameExt;
                    string key = batch.Ip + ":" + batch.Port + ":" + batch.ServiceName + ":" + username;
                    if (succeededKeys.ContainsKey(key))
                    {
                        done += passTotal;
                        continue;
                    }
                    int pi = 0;
                    bool stopUser = false;
                    while (pi < passTotal && !stopUser && !abandoned && !StopAll)
                    {
                        ct.ThrowIfCancellationRequested();
                        int take = Math.Min(64, passTotal - pi);
                        var chunk = new List<string>(take);
                        for (int i = 0; i < take; i++)
                        {
                            chunk.Add(CredentialExpander.Expand(user, passSnapshot[passStart + pi + i]));
                        }
                        Dictionary<string, AuthResult> results;
                        try
                        {
                            if (fan == null)
                            {
                                CheckerRegistry.TryCreate(batch.ServiceName, out CheckerBase cb);
                                fan = (IFanOutAuth)cb;
                                fan.Connect(batch.Ip, batch.Port, opt.TimeoutSec);
                            }
                            results = fan.TryAuthMany(username, chunk);
                        }
                        catch (Exception e)
                        {
                            try { fan?.Dispose(); } catch { }
                            fan = null;
                            if (++reconnects > opt.RetryCount)
                            {
                                Log("检查" + batch.Ip + ":" + batch.Port + " 连接反复失败，放弃该目标！" + e.Message);
                                abandoned = true;
                            }
                            continue;
                        }
                        if (results.Count == 0)
                        {
                            // 整窗无应答：目标不可达或丢包，不计进度重试
                            try { fan?.Dispose(); } catch { }
                            fan = null;
                            if (++reconnects > opt.RetryCount)
                            {
                                Log("检查" + batch.Ip + ":" + batch.Port + " 持续无应答，放弃该目标！");
                                abandoned = true;
                            }
                            System.Threading.Thread.Sleep(500);
                            continue;
                        }
                        reconnects = 0;
                        foreach (string npass in chunk)
                        {
                            done++;
                            pi++;
                            Interlocked.Increment(ref _allCrackCount);
                            if (results.TryGetValue(npass, out AuthResult r) && r == AuthResult.Success)
                            {
                                HandleAuthSuccess(key, batch.Ip, batch.Port, batch.ServiceName, username, npass, fan.Banner, 0);
                                stopUser = true;
                                break; // 剩余 chunk 成员计入下面 done 补差
                            }
                        }
                    }
                    if (stopUser)
                    {
                        done += passTotal - pi;
                    }
                }
                long skipped = targetTotal - done;
                if (skipped > 0)
                {
                    Interlocked.Add(ref _allCrackCount, skipped);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception e)
            {
                Log(e.Message + e.StackTrace);
            }
            finally
            {
                try { fan?.Dispose(); } catch { }
                if (acquired)
                {
                    gate.Release();
                }
                Interlocked.Decrement(ref _activeAuthCount);
            }
        }
    }
}
