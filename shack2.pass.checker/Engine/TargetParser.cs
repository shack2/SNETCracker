using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Tools;

namespace SNETCracker.Engine
{
    /// <summary>
    /// 目标地址解析：单 IP、域名、IP 范围（a.b.c.d-e.f.g.h，支持跨段）、CIDR（a.b.c.d/mask）。
    /// 从 MainViewModel 抽出，UI 与 CLI 共用同一份解析逻辑。
    /// </summary>
    public static class TargetParser
    {
        /// <summary>单行展开地址数上限，防止误输 /0 之类的大段导致内存暴涨</summary>
        private const int MaxTargetsPerLine = 65536;

        /// <summary>解析多行目标文本为去重后的目标列表；无效行通过 log 回调记录并跳过。</summary>
        public static List<string> ParseLines(IEnumerable<string> lines, Action<string> log)
        {
            var targetList = new List<string>();
            var targetSet = new HashSet<string>();
            foreach (string raw in lines)
            {
                ParseTargetLine((raw ?? "").Trim(), targetList, targetSet, log);
            }
            return targetList;
        }

        /// <summary>单行目标解析：无效行记录日志并跳过。</summary>
        public static void ParseTargetLine(string line, List<string> targetList, HashSet<string> targetSet, Action<string> log)
        {
            if (line.Length == 0)
            {
                return;
            }

            // CIDR：192.168.1.0/24
            if (line.Contains('/'))
            {
                string[] parts = line.Split('/');
                if (parts.Length == 2 && TryParseIPv4(parts[0], out uint baseIp) &&
                    int.TryParse(parts[1], out int mask) && mask >= 0 && mask <= 32)
                {
                    uint hostMask = mask == 0 ? 0xFFFFFFFFu : (1u << (32 - mask)) - 1;
                    uint network = baseIp & ~hostMask;
                    uint broadcast = network | hostMask;
                    // /31、/32 保留全部地址；其余跳过网络地址与广播地址
                    uint start = mask <= 30 ? network + 1 : network;
                    uint end = mask <= 30 ? broadcast - 1 : broadcast;
                    AddTargetRange(start, end, line, targetList, targetSet, log);
                }
                else
                {
                    log?.Invoke("目标行格式错误（CIDR）：" + line);
                }
                return;
            }

            // IP 范围：192.168.1.1-192.168.1.200（两段都是 IPv4 才按范围处理，否则可能是带 '-' 的域名）
            int dash = line.IndexOf('-');
            if (dash > 0 &&
                TryParseIPv4(line.Substring(0, dash), out uint startIp) &&
                TryParseIPv4(line.Substring(dash + 1), out uint endIp))
            {
                AddTargetRange(startIp, endIp, line, targetList, targetSet, log);
                return;
            }

            // 单 IP
            if (TryParseIPv4(line, out uint single))
            {
                AddTarget(single, targetList, targetSet);
                return;
            }

            // 域名
            if (Regex.IsMatch(line, "^[\\w\\-\\.]{1,100}[a-zA-Z]{1,8}$"))
            {
                if (targetSet.Add(line))
                {
                    targetList.Add(line);
                }
                return;
            }

            log?.Invoke("目标行格式错误：" + line);
        }

        private static void AddTargetRange(uint start, uint end, string line, List<string> targetList, HashSet<string> targetSet, Action<string> log)
        {
            if (end < start)
            {
                log?.Invoke("目标范围起始地址大于结束地址：" + line);
                return;
            }
            ulong count = (ulong)end - start + 1;
            if (count > MaxTargetsPerLine)
            {
                log?.Invoke("目标行 " + line + " 包含 " + count + " 个地址，超过单行上限 " + MaxTargetsPerLine + "，已跳过");
                return;
            }
            for (uint v = start; ; v++)
            {
                AddTarget(v, targetList, targetSet);
                if (v == end)
                {
                    break;
                }
            }
        }

        private static void AddTarget(uint ip, List<string> targetList, HashSet<string> targetSet)
        {
            string s = (ip >> 24) + "." + ((ip >> 16) & 255) + "." + ((ip >> 8) & 255) + "." + (ip & 255);
            if (targetSet.Add(s))
            {
                targetList.Add(s);
            }
        }

        /// <summary>严格 IPv4 解析：必须为 4 个 0-255 的十进制段（拒绝 999.1.1.1、127.1 简写等）</summary>
        public static bool TryParseIPv4(string s, out uint value)
        {
            value = 0;
            string[] parts = s.Split('.');
            if (parts.Length != 4)
            {
                return false;
            }
            foreach (string part in parts)
            {
                if (part.Length == 0 || part.Length > 3 || !part.All(char.IsDigit) || !byte.TryParse(part, out byte b))
                {
                    return false;
                }
                value = (value << 8) | b;
            }
            return true;
        }

        /// <summary>校验单行目标格式是否合法（无副作用，供目标文件导入时过滤）。支持：单 IP、域名、IP 范围、CIDR。</summary>
        public static bool IsValidLine(string line)
        {
            line = (line ?? "").Trim();
            if (line.Length == 0)
            {
                return false;
            }
            if (line.Contains('/'))
            {
                string[] parts = line.Split('/');
                return parts.Length == 2 && TryParseIPv4(parts[0], out _) &&
                       int.TryParse(parts[1], out int mask) && mask >= 0 && mask <= 32;
            }
            int dash = line.IndexOf('-');
            if (dash > 0 && TryParseIPv4(line.Substring(0, dash), out _) && TryParseIPv4(line.Substring(dash + 1), out _))
            {
                return true;
            }
            if (TryParseIPv4(line, out _))
            {
                return true;
            }
            return Regex.IsMatch(line, "^[\\w\\-\\.]{1,100}[a-zA-Z]{1,8}$");
        }
    }

    /// <summary>字典加载：存在的文件路径 → 按行读字典；否则非空文本 → 单个值；空 → 空集合。</summary>
    public static class DicLoader
    {
        public static HashSet<string> LoadDicOrSingle(string text)
        {
            string t = (text ?? "").Trim();
            if (t.Length > 0 && File.Exists(t))
            {
                return FileTool.readFileToList(t);
            }
            var set = new HashSet<string>();
            if (t.Length > 0)
            {
                set.Add(t);
            }
            return set;
        }
    }
}
