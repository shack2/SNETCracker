---
name: SPasswordCheckerV2.SKILL
description: 用本地 CLI 工具 spc（Windows/Linux Native AOT 单文件，每个约 7 MB）对网络服务做弱口令/弱密码检测。当用户要求扫描或验证主机、网段、服务的弱密码（如 SSH/RDP/MySQL/Redis/MongoDB 等 42 种协议的密码审计、凭据验证、爆破测试、口令强度检查）时使用。触发词：弱口令、弱密码、密码审计、password audit、weak password、credential check、口令爆破验证。
---

# spc 弱口令检测

- `bin/spc.exe`：Windows x64 可执行文件。
- `bin/spc`：Linux x64 可执行文件，首次使用前执行 `chmod +x ./spc`。

两者均为 Native AOT 单文件工具（每个约 7 MB），无需 .NET 运行时。工作目录必须设为 `bin/`（程序按相对路径读取 `config/`）。使用 `--version` 查看版本、`--help` 查看完整参数。本文 Windows 示例使用 `./spc.exe`，Linux 下替换为 `./spc`。

## 输出契约（AI 调用必读）

- **stdout 只输出命中结果**：每行 `[+] ip:port\t服务\t用户名\t密码\tbanner`；加 `--json` 则为 JSON 行（字段 ip/port/service/username/password/banner/useTime）。
- 过程日志走 **stderr**；`-q` 静默日志。stdout 解析不到 `[+]` 或 JSON 行即未命中。
- 退出码：0=正常（含未命中），1=参数/运行错误。
- 结束行 `[done] 目标 N 个，存活服务 N 个，尝试 A/B，命中 N 个，用时 X 秒` 在 stderr。

## 常用命令

```bash
cd bin
# 单目标 + 已知凭据验证
./spc.exe -t 192.168.1.10 -s SSH -u root -p 123456
# 网段 + 内置字典自动匹配（不给凭据时默认即此模式）
./spc.exe -t 192.168.1.0/24 -s SSH,MySQL,Redis --auto-dic
# IP 区间 + 文件字典 + JSON 输出
./spc.exe -t 10.0.0.1-10.0.0.200 -s RDP -U users.txt -P pass.txt --json
# 非标端口：目标上用 ip:port 覆盖默认端口
./spc.exe -t 192.168.1.10:2222 -s SSH -u root -p 123456
```

## 参数速查

| 参数 | 说明 |
|---|---|
| `-t / -T` | 目标（单IP/域名/CIDR/IP段，换行/逗号/分号分隔）/ 目标文件 |
| `-s` | 逗号分隔服务名；省略则探测全部 42 种 |
| `-u / -U / -p / -P` | 单值（可重复）/ 字典文件；空密码用 `-p ""` |
| `--auto-dic` | 按服务用内置字典 `config/dic/dic_{user,password}_<服务>.txt` |
| `--threads / --timeout / --retry` | 并发 30 / 单次超时 15 秒 / 重试 0 |
| `--stop-on-success` | 成功破解任意一个账号后停止所有剩余任务 |
| `--shard <n>` | 连接复用协议的密码分片数（默认 1），单目标大字典时并行加速 |
| `--per-host <n>` | 单主机认证并发上限（默认 0=不限），防全部线程压同一台机器 |
| `--lockout-limit <n>` | 防账号锁定熔断阈值（默认 50），严格环境建议 5~10 |
| `--no-failfast` | 关闭死主机短路（默认开启：连续 5 次纯超时判死并跳过该主机剩余端口） |
| `--no-port-scan` | 跳过端口探测直接认证 |
| `--suffix` | 账号后缀，如 `@corp.com` |
| `-o / --json / -q` | 命中写文件 / JSON 行 / 静默 |

## 自更新

```bash
./spc.exe --update   # 检查更新：有新版自动下载 zip 更新包到软件运行目录，结果行在 stdout
```

配置 `config/update.ini`（server/appId/channel/key/enabled）。`--update` 会按当前操作系统和架构获取对应平台包。stdout 结果：`[update] 已是最新版本 X` 或 `[update] 已下载 X（N 个文件）到 <目录>`；未命中更新时退出码也是 0。

## 要点

- 服务清单与默认端口在 `config/service.ini`（SSH、RDP、SMB、MySQL、SQLServer、Oracle、FTP、MongoDB、PostgreSQL、Telnet、SMTP/POP3/IMAP 及 SSL 变体、VNC、Redis、Kingbase、ClickHouse、DB2、DM、Memcached、SVN、Tomcat、WebLogic、SNMP、LDAP/LDAP_SSL、Elasticsearch、Zookeeper、HTTP/HTTPS、MQTT、Rsync、FTP_SSL、RabbitMQ、Kafka、Cassandra、Neo4j、ActiveMQ、WinRM）。
- Redis/VNC 等无用户名协议：只给 `-p` 即可，勿加 `-u`。
- Oracle 服务名在 `config/oracle.txt`（默认探测回退 orcl）；DB2 库名在 `config/db2.txt`。
- 内置字典可直接编辑 `config/dic/` 下对应 txt 定制。
- 仅对有授权的目标使用；大范围扫描建议 `--threads 50 --timeout 10` 并配合 `-o` 落盘。
