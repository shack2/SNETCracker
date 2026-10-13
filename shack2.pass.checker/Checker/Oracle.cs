using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Tools;

namespace SNETCracker.Checker
{
    /// <summary>
    /// Oracle 弱口令检测：自实现最小客户端（OracleWire），
    /// TNS 握手 + O5Logon（11g）/ O3Logon（10g）认证，替代 Oracle.ManagedDataAccess.Core。
    /// 服务名自动探测：TNS 登录必须先给出正确的 SERVICE_NAME，否则连认证都进不去。
    /// 按 配置值 → orcl → xe → orclcdb → pdborcl 顺序探测（TNS-12514 换下一个），
    /// 命中后按目标（ip:port）缓存，多线程共享 —— 同一目标全部凭据尝试复用，
    /// 不会每个密码都重新探测；并发竞态至多重复探测一次，结果一致无害。
    /// </summary>
    class Oracle : CheckerBase
    {
        /// <summary>服务名解析缓存（ip:port -> serviceName）。开局由 MainViewModel 调 ClearServiceNameCache 重置。</summary>
        private static readonly ConcurrentDictionary<string, string> serviceNameCache = new ConcurrentDictionary<string, string>();

        /// <summary>握手流程缓存（ip:port -> 是否 12.2+/21c 现代流程），避免同一目标每次先试老流程被断连。</summary>
        private static readonly ConcurrentDictionary<string, bool> modernFlowCache = new ConcurrentDictionary<string, bool>();

        private static readonly string[] DefaultServiceNames = { "orcl", "xe", "orclcdb", "pdborcl" };

        /// <summary>新一轮检测前清空缓存（目标可能重装/改配置）。</summary>
        public static void ClearServiceNameCache()
        {
            serviceNameCache.Clear();
            modernFlowCache.Clear();
        }

        private readonly String orclName = FileTool.readFileToString(AppDomain.CurrentDomain.BaseDirectory + "/config/oracle.txt");

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            string pass = "空".Equals(password) ? "" : password;
            string targetKey = ip + ":" + port;
            bool? modernHint = modernFlowCache.TryGetValue(targetKey, out bool m) ? m : (bool?)null;

            // 缓存命中：直接认证，不再探测
            if (serviceNameCache.TryGetValue(targetKey, out string cached))
            {
                using (OracleWire hit = new OracleWire())
                {
                    hit.Connect(ip, port, cached, timeOut, modernHint);
                    modernFlowCache[targetKey] = hit.IsModernFlow;
                    if (hit.Login(username, pass, out _))
                    {
                        server.isSuccess = true;
                        server.banner = hit.Banner();
                    }
                }
                return server;
            }

            // 未命中：逐个候选探测，TNS-12514（服务名不可识别）换下一个，其余异常直接抛出
            var tried = new List<string>();
            foreach (string candidate in Candidates())
            {
                using (OracleWire conn = new OracleWire())
                {
                    try
                    {
                        conn.Connect(ip, port, candidate, timeOut, modernHint);
                    }
                    catch (OracleWire.OracleServiceUnknownException)
                    {
                        tried.Add(candidate);
                        continue;
                    }
                    serviceNameCache[targetKey] = candidate;
                    modernFlowCache[targetKey] = conn.IsModernFlow;
                    if (conn.Login(username, pass, out _))
                    {
                        server.isSuccess = true;
                        server.banner = conn.Banner();
                    }
                    return server;
                }
            }
            throw new Exception("Oracle 服务名不可识别（已尝试 " + string.Join(",", tried) +
                                "），请在 config/oracle.txt 配置正确的服务名");
        }

        /// <summary>候选服务名：配置值优先，后跟常见默认值，去空去重（忽略大小写）。</summary>
        private IEnumerable<string> Candidates()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string cfg = orclName == null ? "" : orclName.Trim();
            if (cfg.Length > 0 && seen.Add(cfg))
            {
                yield return cfg;
            }
            foreach (string sn in DefaultServiceNames)
            {
                if (seen.Add(sn))
                {
                    yield return sn;
                }
            }
        }
    }
}
