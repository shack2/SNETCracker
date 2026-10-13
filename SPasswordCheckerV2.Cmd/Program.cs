using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using SNETCracker.Engine;
using SPasswordCheckerV2.Data;
using Tools;

namespace SPasswordCheckerV2.Cmd
{
    /// <summary>
    /// 超级弱口令检查工具 命令行版（spc）：与 UI 共用 shack2.pass.checker 引擎。
    /// 面向脚本 / AI 智能体调用：参数进、结果出（stdout=结果，stderr=过程日志），
    /// 退出码 0=正常完成（有无命中都正常），1=参数/环境错误。
    ///
    /// 示例：
    ///   spc -t 192.168.1.10 -s SSH -u root -p 123456
    ///   spc -T targets.txt -s SSH,MySQL -U users.txt -P passwords.txt --threads 50
    ///   spc -t 192.168.1.0/24 -s MySQL --auto-dic -o result.txt
    ///   spc -t 192.168.1.10 -s Redis -p "" --json
    /// </summary>
    internal static class Program
    {
        private static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            try
            {
                return MainCore(args);
            }
            catch (Exception e)
            {
                // 兜底：参数/文件/环境错误一律干净报错 + 退出码 1，不甩堆栈给调用方
                Console.Error.WriteLine("错误：" + e.Message);
                return 1;
            }
        }

        private static int MainCore(string[] args)
        {
            if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
            {
                PrintUsage();
                return args.Length == 0 ? 1 : 0;
            }

            // ---------- 参数解析 ----------
            var targets = new List<string>();
            var users = new HashSet<string>();
            var passes = new HashSet<string>();
            List<string> serviceFilter = null;
            bool autoDic = false, portScan = true, json = false, quiet = false;
            bool stopOnSuccess = false, hostFailFast = true;
            int threads = 30, timeout = 15, retry = 0, shard = 1, perHost = 0, lockoutLimit = 50;
            string suffix = "", output = null;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                string Next() => i + 1 < args.Length ? args[++i] : null;
                switch (a)
                {
                    case "-t": case "--target":
                        AddTargets(targets, Next()); break;
                    case "-T": case "--target-file":
                        AddTargets(targets, File.ReadAllText(Require(Next(), a))); break;
                    case "-u": case "--user":
                        users.Add(Next() ?? ""); break;
                    case "-U": case "--user-file":
                        Union(users, FileTool.readFileToList(Require(Next(), a))); break;
                    case "-p": case "--pass":
                        passes.Add(Next() ?? ""); break;
                    case "-P": case "--pass-file":
                        Union(passes, FileTool.readFileToList(Require(Next(), a))); break;
                    case "-s": case "--services":
                        serviceFilter = (Next() ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList(); break;
                    case "--suffix": suffix = Next() ?? ""; break;
                    case "--threads": threads = ParseInt(Require(Next(), a), a, 1); break;
                    case "--timeout": timeout = ParseInt(Require(Next(), a), a, 1); break;
                    case "--retry": retry = ParseInt(Require(Next(), a), a, 0); break;
                    case "--shard": shard = ParseInt(Require(Next(), a), a, 1); break;
                    case "--per-host": perHost = ParseInt(Require(Next(), a), a, 0); break;
                    case "--lockout-limit": lockoutLimit = ParseInt(Require(Next(), a), a, 1); break;
                    case "--no-failfast": hostFailFast = false; break;
                    case "--stop-on-success": stopOnSuccess = true; break;
                    case "--auto-dic": autoDic = true; break;
                    case "--no-port-scan": portScan = false; break;
                    case "-o": case "--output": output = Require(Next(), a); break;
                    case "--json": json = true; break;
                    case "-q": case "--quiet": quiet = true; break;
                    case "-v": case "--version":
                        Console.WriteLine("spc " + SoftUpdateClient.GetAssemblyVersion());
                        return 0;
                    case "--update": return RunUpdate();
                    default:
                        Console.Error.WriteLine("未知参数：" + a);
                        PrintUsage();
                        return 1;
                }
            }

            // ---------- 服务清单（config/service.ini，可用 -s 过滤） ----------
            string baseDir = AppContext.BaseDirectory;
            var services = new List<ScanService>();
            var svcUsers = new Dictionary<string, HashSet<string>>();
            var svcPasses = new Dictionary<string, HashSet<string>>();
            foreach (string line in FileTool.readFileToList(baseDir + "/config/service.ini"))
            {
                string[] strs = line.Split(':');
                if (strs.Length != 2) continue;
                string name = strs[0];
                if (serviceFilter != null && !serviceFilter.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
                int[] ports = Array.ConvertAll(strs[1].Split(','), int.Parse);
                services.Add(new ScanService(name, ports));
                string dicKey = name.ToLower().Replace("_ssl", "");
                svcUsers[name] = FileTool.readFileToList(baseDir + "/config/dic/dic_username_" + dicKey + ".txt");
                svcPasses[name] = FileTool.readFileToList(baseDir + "/config/dic/dic_password_" + dicKey + ".txt");
            }
            if (services.Count == 0)
            {
                Console.Error.WriteLine("没有可检测的服务（service.ini 为空或 -s 过滤后不匹配）");
                return 1;
            }

            // ---------- 目标解析（支持 ip:port 显式端口覆盖，常见于非标端口服务） ----------
            int? portOverride = null;
            for (int ti = 0; ti < targets.Count; ti++)
            {
                string line = targets[ti].Trim();
                int sep = line.LastIndexOf(':');
                if (sep > 0 && int.TryParse(line.Substring(sep + 1), out int p) && p > 0 && p <= 65535
                    && TargetParser.IsValidLine(line.Substring(0, sep)))
                {
                    if (portOverride.HasValue && portOverride.Value != p)
                    {
                        Console.Error.WriteLine("多个目标指定了不同端口，暂不支持混端口扫描：" + line);
                        return 1;
                    }
                    portOverride = p;
                    targets[ti] = line.Substring(0, sep);
                }
            }
            if (portOverride.HasValue)
            {
                foreach (ScanService sv in services)
                {
                    sv.Ports = new[] { portOverride.Value };
                }
            }
            List<string> targetList = TargetParser.ParseLines(targets, quiet ? null : (Action<string>)(m => Console.Error.WriteLine("[目标] " + m)));
            if (targetList.Count == 0)
            {
                Console.Error.WriteLine("目标为空或格式错误（支持 单IP / 域名 / IP段 / CIDR）");
                return 1;
            }

            // ---------- 字典语义：给了用户/密码 → 全局模式；否则按服务字典 ----------
            if (!autoDic && (users.Count > 0 || passes.Count > 0))
            {
                autoDic = false;
            }
            else if (users.Count == 0 && passes.Count == 0)
            {
                autoDic = true;
            }
            if (!autoDic && passes.Count == 0)
            {
                Console.Error.WriteLine("未提供密码：用 -p/--pass、-P/--pass-file，或 --auto-dic 使用内置字典");
                return 1;
            }

            // ---------- 执行 ----------
            var results = new List<CheckResult>();
            var engine = new ScanEngine();
            if (!quiet)
            {
                engine.LogHandler = m => Console.Error.WriteLine("[log] " + m);
            }
            engine.FoundHandler = cr =>
            {
                lock (results) { results.Add(cr); }
                string line = $"{TsvSafe(cr.IP)}:{cr.Port}\t{TsvSafe(cr.ServiceName)}\t{TsvSafe(cr.Username)}\t{TsvSafe(cr.Password)}\t{TsvSafe(cr.Banner)}";
                if (json)
                {
                    Console.WriteLine(ToJson(cr));
                }
                else
                {
                    Console.WriteLine("[+] " + line);
                }
            };

            var req = new ScanRequest
            {
                Targets = targetList,
                Services = services,
                ServiceUsernames = svcUsers,
                ServicePasswords = svcPasses,
                Usernames = users,
                Passwords = passes
            };
            var opt = new ScanOptions
            {
                Threads = threads,
                TimeoutSec = timeout,
                RetryCount = retry,
                PortScan = portScan,
                AutoDic = autoDic,
                UsernameExt = suffix,
                StopOnSuccess = stopOnSuccess,
                ReuseShardCount = shard,
                HostFailFast = hostFailFast,
                PerHostLimit = perHost,
                LockoutFailLimit = lockoutLimit,
                LogDir = null // CLI 不写文件日志，日志全走 stderr
            };

            var sw = System.Diagnostics.Stopwatch.StartNew();
            // Ctrl+C 优雅停止：取消令牌通知引擎停止枚举新任务，已命中的结果保留并照常输出汇总
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };
            bool cancelled = false;
            try
            {
                engine.Run(req, opt, cts.Token);
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("扫描异常终止：" + e.Message);
                return 1;
            }
            sw.Stop();

            // ---------- 汇总 ----------
            Console.Error.WriteLine($"[done] {(cancelled ? "已取消：" : "")}目标 {targetList.Count} 个，存活服务 {engine.aliveTargetCount} 个，" +
                $"尝试 {engine.allCrackCount}/{engine.checkSumCount}，命中 {engine.checkSuccessCount} 个，用时 {sw.Elapsed.TotalSeconds:F1} 秒");
            if (output != null)
            {
                var sb = new StringBuilder();
                foreach (CheckResult cr in results)
                {
                    sb.Append(cr.Index).Append("----").Append(cr.ServiceName).Append("----").Append(cr.IP)
                      .Append("----").Append(cr.Port).Append("----").Append(cr.Username).Append("----").Append(cr.Password)
                      .Append('\n');
                }
                File.WriteAllText(output, sb.ToString());
                Console.Error.WriteLine("[done] 结果已写入 " + output);
            }
            return 0;
        }

        private static void AddTargets(List<string> targets, string text)
        {
            if (text == null) return;
            // 支持换行 / 逗号 / 分号分隔的混合输入
            foreach (string line in text.Split(new[] { '\n', '\r', ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                targets.Add(line);
            }
        }

        private static void Union(HashSet<string> set, HashSet<string> items)
        {
            foreach (string s in items) set.Add(s);
        }

        private static string Require(string v, string flag)
        {
            if (v == null) throw new ArgumentException("参数 " + flag + " 缺少值");
            return v;
        }

        /// <summary>数值参数解析：非数字/越界给友好报错（由 Main 兜底转退出码 1）</summary>
        private static int ParseInt(string v, string flag, int min)
        {
            if (!int.TryParse(v, out int n))
            {
                throw new ArgumentException("参数 " + flag + " 的值不是有效数字：" + v);
            }
            if (n < min)
            {
                throw new ArgumentException("参数 " + flag + " 必须 ≥ " + min + "（当前 " + n + "）");
            }
            return n;
        }

        /// <summary>手写 JSON（AOT 安全，不依赖反射序列化）；完整转义控制字符——banner 来自不可信远端，含 \n\t 时不能产出非法 JSON 行</summary>
        private static string ToJson(CheckResult cr)
        {
            return "{\"ip\":" + JsonStr(cr.IP) + ",\"port\":" + cr.Port + ",\"service\":" + JsonStr(cr.ServiceName)
                + ",\"username\":" + JsonStr(cr.Username) + ",\"password\":" + JsonStr(cr.Password)
                + ",\"banner\":" + JsonStr(cr.Banner) + ",\"useTime\":" + cr.UseTime + "}";
        }

        private static string JsonStr(string s)
        {
            if (string.IsNullOrEmpty(s)) return "\"\"";
            var sb = new StringBuilder(s.Length + 2);
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        /// <summary>TSV 行净化：字段内的 Tab/换行替换为空格，防止单行结果被撑成多行错位</summary>
        private static string TsvSafe(string s)
        {
            return (s ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
        }

        /// <summary>
        /// 自更新检查（对接 SoftUpdate 更新服务，config/update.ini 配置）：
        /// 有新版则下载 zip 更新包到软件运行目录（SHA256 校验 + 已有包哈希复用），结果输出到 stdout 供脚本解析。
        /// </summary>
        private static int RunUpdate()
        {
            try
            {
                var cfg = SoftUpdateConfig.Load(AppContext.BaseDirectory + "/config/update.ini");
                if (!cfg.Enabled)
                {
                    Console.Error.WriteLine("[update] 未启用（config/update.ini enabled=false）");
                    return 0;
                }
                string cur = SoftUpdateClient.GetAssemblyVersion();
                var client = new SoftUpdateClient(cfg, cur);
                var result = client.CheckAsync().GetAwaiter().GetResult();
                if (result == null)
                {
                    Console.Error.WriteLine("[update] 未配置更新服务地址（config/update.ini server=）");
                    return 1;
                }
                if (!result.HasUpdate || result.Manifest == null)
                {
                    Console.WriteLine("[update] 已是最新版本 " + cur);
                    return 0;
                }
                var m = result.Manifest;
                Console.Error.WriteLine("[update] 发现新版本 " + m.Version + "（当前 " + cur + "），开始下载...");
                string dir = AppContext.BaseDirectory; // 更新包下载到软件运行目录
                client.DownloadAsync(m, dir).GetAwaiter().GetResult();
                Console.WriteLine("[update] 已下载 " + m.Version + "（" + m.Files.Length + " 个文件）到 " + dir);
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[update] 更新异常：" + e.Message);
                return 1;
            }
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine(@"超级弱口令检查工具 命令行版（spc）

用法：spc -t <目标> -s <服务> [选项]
      spc --update    检查更新，有新版时下载 zip 更新包到软件运行目录（配置 config/update.ini）
      spc --version   输出版本号（stdout）

目标：
  -t, --target <目标>       单IP/域名/IP段(1.1.1.1-1.1.1.200)/CIDR(1.1.1.0/24)，可用换行/逗号/分号分隔多个；
                            支持 ip:port 显式指定非标端口（覆盖 service.ini 默认端口，需全部目标同端口）
  -T, --target-file <文件>  从文件读取目标列表（每行一个）

凭据（不给则默认 --auto-dic 用内置服务字典）：
  -u, --user <用户名>       单个用户名（可重复）
  -U, --user-file <文件>    用户名字典
  -p, --pass <密码>         单个密码（可重复；空密码用 -p """"）
  -P, --pass-file <文件>    密码字典
      --auto-dic           按服务自动选择内置字典（config/dic/）
      --suffix <后缀>       账号后缀，如 @test.com

范围与参数：
  -s, --services <列表>     逗号分隔服务名（默认全部）：SSH,RDP,MySQL,SQLServer,Oracle,Redis...
      --threads <n>        认证并发（默认 30）
      --timeout <秒>       单次认证超时（默认 15）
      --retry <n>          异常重试次数（默认 0）
      --stop-on-success    成功破解任意一个账号后停止所有剩余任务
      --shard <n>          连接复用协议的密码分片数（默认 1；单目标大字典时可并行加速，
                           每片一条连接，过多易触发服务端防爆破限制）
      --per-host <n>       单主机认证并发上限（默认 0=不限；防全部线程压同一台机器）
      --lockout-limit <n>  防账号锁定熔断阈值（默认 50；严格环境建议 5~10）
      --no-failfast        关闭死主机短路（端口探测中连续超时判死并跳过其剩余端口，默认开启）
      --no-port-scan       跳过端口开放探测，直接认证

输出：
  -o, --output <文件>      命中结果写文件
      --json               命中结果以 JSON 行输出（stdout）
  -q, --quiet              静默（不输出过程日志）

约定：stdout 只输出命中的弱口令结果，过程日志走 stderr；退出码 0=正常，1=错误。");
        }
    }
}
