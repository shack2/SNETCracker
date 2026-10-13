using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Tools;

namespace SNETCracker.Checker
{
    /// <summary>
    /// DB2 弱口令检测：自实现最小客户端（Db2Wire），
    /// DRDA 协议 EXCSAT + ACCSEC 探测 + SECCHK 明文口令认证，替代 IBM DB2 驱动。
    /// 库名自动探测：DRDA 登录（RDBNAM）必须先给出正确的数据库名，否则认证被拒绝。
    /// 按 配置值(config/db2.txt) → testdb → toolsdb → sample → test → db2 顺序探测
    /// （RDBNFNRM 换下一个），命中后按目标（ip:port）缓存，多线程共享 —— 同一目标
    /// 全部凭据尝试复用，不会每个密码都重新探测；并发竞态至多重复探测一次，结果一致无害。
    /// </summary>
    class DB2 : CheckerBase
    {
        /// <summary>库名解析缓存（ip:port -> dbname）。开局由 MainViewModel 调 ClearDbNameCache 重置。</summary>
        private static readonly ConcurrentDictionary<string, string> dbNameCache = new ConcurrentDictionary<string, string>();

        private static readonly string[] DefaultDbNames = { "testdb", "toolsdb", "sample", "test", "db2" };

        /// <summary>新一轮检测前清空缓存（目标可能重装/改配置）。</summary>
        public static void ClearDbNameCache()
        {
            dbNameCache.Clear();
        }

        private readonly String cfgDbName = FileTool.readFileToString(AppDomain.CurrentDomain.BaseDirectory + "/config/db2.txt");

        public override Server Crack(String ip, int port, String username, String password, int timeOut)
        {
            Server server = new Server();
            string pass = "空".Equals(password) ? "" : password;
            string targetKey = ip + ":" + port;

            // 缓存命中：探测 + 认证一条连接内完成
            if (dbNameCache.TryGetValue(targetKey, out string cached))
            {
                using (Db2Wire hit = new Db2Wire())
                {
                    hit.Connect(ip, port, timeOut);
                    hit.Probe(cached);
                    if (hit.Login(username, pass, cached, out _))
                    {
                        server.isSuccess = true;
                        server.banner = hit.Banner();
                    }
                }
                return server;
            }

            // 未命中：逐个候选探测，RDBNFNRM（库不存在）换下一个，其余异常直接抛出
            var tried = new List<string>();
            foreach (string candidate in Candidates())
            {
                using (Db2Wire conn = new Db2Wire())
                {
                    conn.Connect(ip, port, timeOut);
                    try
                    {
                        conn.Probe(candidate);
                    }
                    catch (Db2Wire.DbNotFoundException)
                    {
                        tried.Add(candidate);
                        continue;
                    }
                    dbNameCache[targetKey] = candidate;
                    if (conn.Login(username, pass, candidate, out _))
                    {
                        server.isSuccess = true;
                        server.banner = conn.Banner();
                    }
                    return server;
                }
            }
            throw new Exception("DB2 数据库名不可识别（已尝试 " + string.Join(",", tried) +
                                "），请在 config/db2.txt 配置正确的数据库名");
        }

        /// <summary>候选库名：配置值优先，后跟常见默认值，去空去重（忽略大小写）。</summary>
        private IEnumerable<string> Candidates()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string cfg = cfgDbName == null ? "" : cfgDbName.Trim();
            if (cfg.Length > 0 && seen.Add(cfg))
            {
                yield return cfg;
            }
            foreach (string dn in DefaultDbNames)
            {
                if (seen.Add(dn))
                {
                    yield return dn;
                }
            }
        }
    }
}
