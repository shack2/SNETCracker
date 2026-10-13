# SNETCracker V2 · 超级弱口令检查工具

跨平台弱口令/弱密码检测工具，支持 **42 种协议** 的密码验证，提供 **GUI 客户端** 与 **命令行（spc）** 双形态。

V2 为全新重写版本（Avalonia + Native AOT，全协议自实现）。旧版 WinForms 代码见 `v1-legacy` 标签。

## 特性

- **42 种协议**：SSH / RDP / SMB / MySQL / SQLServer / PostgreSQL / Oracle / Redis / MongoDB / FTP / Telnet / VNC / SNMP / LDAP / WinRM / HTTP(S) / SMTP / POP3 / IMAP / MQTT / Kafka / RabbitMQ / ActiveMQ / Zookeeper / Cassandra / Neo4j / Elasticsearch / Memcached / SVN / Tomcat / WebLogic / DB2 / DM / Kingbase / ClickHouse / Rsync 等
- **协议自实现**：SSH/MySQL/PG/Oracle/TDS/Mongo/Redis/FTP/邮件等均为最小化纯 C# 实现，零重型第三方依赖
- **Native AOT**：单文件免安装，Windows / Linux / macOS 全平台
- **大网段优化**：CIDR 批量目标、死主机短路、单机并发限流、账号熔断防锁定、SSH 单连接多密码复用
- **CLI（spc）**：stdout 只输出命中结果（`[+]` 行 / JSON），可直接作为脚本或 AI 智能体工具调用

## 下载

见 [Releases](https://github.com/shack2/SNETCracker/releases)：每个平台包内含 GUI 客户端与 spc 命令行两个可执行文件及 `config/` 配置。

## 构建

```bash
dotnet publish SPasswordCheckerV2/SPasswordCheckerV2.csproj -c Release -r win-x64      # GUI
dotnet publish SPasswordCheckerV2.Cmd/SPasswordCheckerV2.Cmd.csproj -c Release -r win-x64  # CLI
```

## 项目结构

| 目录 | 说明 |
| --- | --- |
| `SPasswordCheckerV2/` | Avalonia GUI 客户端 |
| `SPasswordCheckerV2.Cmd/` | 命令行版本（spc） |
| `shack2.pass.checker/` | 协议检测核心库（42 协议自实现 + 扫描引擎） |
| `SPasswordCheckerV2.SKILL/` | Kimi 智能体技能包定义 |

## 声明

本工具仅供**授权安全测试**与自查使用，请遵守当地法律法规，勿对未授权目标使用。
