using System;
using System.Collections.Generic;

namespace SNETCracker.Checker
{
    /// <summary>
    /// 检测器静态注册表：服务名 → 工厂委托。
    /// 替代 Type.GetType + Activator.CreateInstance 反射分发：
    /// Native AOT 下动态反射查找会被裁剪导致检测器失效，显式 new 则类型被静态引用、必然保留；
    /// 对 JIT 运行也省掉了每次认证的类型查找开销。
    /// 新增检测器时必须在此登记，否则 UI 里选了也无法执行。
    /// </summary>
    public static class CheckerRegistry
    {
        private static readonly Dictionary<string, Func<CheckerBase>> factories =
            new Dictionary<string, Func<CheckerBase>>(StringComparer.OrdinalIgnoreCase)
            {
                { "SSH", () => new SSH() },
                { "RDP", () => new RDP() },
                { "SMB", () => new SMB() },
                { "MySQL", () => new MySQL() },
                { "SQLServer", () => new SQLServer() },
                { "Oracle", () => new Oracle() },
                { "FTP", () => new FTP() },
                { "MongoDB", () => new MongoDB() },
                { "PostgreSQL", () => new PostgreSQL() },
                { "Telnet", () => new Telnet() },
                { "SMTP", () => new SMTP() },
                { "SMTP_SSL", () => new SMTP_SSL() },
                { "POP3", () => new POP3() },
                { "POP3_SSL", () => new POP3_SSL() },
                { "IMAP", () => new IMAP() },
                { "IMAP_SSL", () => new IMAP_SSL() },
                { "VNC", () => new VNC() },
                { "Redis", () => new Redis() },
                { "Kingbase", () => new Kingbase() },
                { "ClickHouse", () => new ClickHouse() },
                { "DB2", () => new DB2() },
                { "DM", () => new DM() },
                { "Memcached", () => new Memcached() },
                { "SNMP", () => new SNMP() },
                { "LDAP", () => new LDAP() },
                { "SVN", () => new SVN() },
                { "Zookeeper", () => new Zookeeper() },
                { "Tomcat", () => new Tomcat() },
                { "WebLogic", () => new WebLogic() },
                { "Elasticsearch", () => new Elasticsearch() },
                { "HTTP", () => new HttpBasic() },
                { "HTTPS", () => new HttpsBasic() },
                { "LDAP_SSL", () => new LDAP_SSL() },
                { "FTP_SSL", () => new FTP_SSL() },
                { "WinRM", () => new WinRm() },
                { "ActiveMQ", () => new ActiveMq() },
                { "MQTT", () => new MQTT() },
                { "Rsync", () => new Rsync() },
                { "RabbitMQ", () => new RabbitMQ() },
                { "Kafka", () => new Kafka() },
                { "Cassandra", () => new Cassandra() },
                { "Neo4j", () => new Neo4j() },
            };

        /// <summary>按服务名创建检测器实例；未注册返回 false。</summary>
        public static bool TryCreate(string serviceName, out CheckerBase checker)
        {
            if (serviceName != null && factories.TryGetValue(serviceName, out Func<CheckerBase> factory))
            {
                checker = factory();
                return true;
            }
            checker = null;
            return false;
        }

        /// <summary>已注册的服务名集合（供自检/测试比对 service.ini 覆盖度）</summary>
        public static IEnumerable<string> RegisteredNames
        {
            get { return factories.Keys; }
        }

        /// <summary>
        /// 每轮检测开始前统一清空各检测器的按目标缓存（Oracle 服务名、DB2 库名探测等）。
        /// 新增带缓存的检测器时在此登记清理动作 —— 与工厂注册同文件，避免遗漏。
        /// </summary>
        public static void ClearAllTargetCaches()
        {
            Oracle.ClearServiceNameCache();
            DB2.ClearDbNameCache();
        }
    }

    /// <summary>凭据展开：字典密码模式 → 实际密码（"空"→空串，%user% 变量替换）。</summary>
    internal static class CredentialExpander
    {
        public static string Expand(string user, string passPattern)
        {
            if (passPattern == null || "空".Equals(passPattern))
            {
                return "";
            }
            return passPattern.Replace("%user%", user ?? "");
        }
    }
}
