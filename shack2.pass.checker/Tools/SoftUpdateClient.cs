using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Tools
{
    /// <summary>更新服务连接配置（config/update.ini，key=value 逐行，# 注释）。</summary>
    public class SoftUpdateConfig
    {
        public string Server = "";      // 更新服务地址，如 http://192.168.1.10:5900
        public string AppId = "spassword-checker";
        public string Channel = "stable";
        public string Key = "";         // 客户端 AES Key（64 位十六进制，服务端启动横幅/管理接口获取）
        public bool Enabled = true;     // false 时启动不再自动检测

        public static SoftUpdateConfig Load(string path)
        {
            var cfg = new SoftUpdateConfig();
            try
            {
                if (!File.Exists(path)) return cfg;
                foreach (string raw in File.ReadAllLines(path))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string k = line.Substring(0, eq).Trim().ToLowerInvariant();
                    string v = line.Substring(eq + 1).Trim();
                    switch (k)
                    {
                        case "server": cfg.Server = v.TrimEnd('/'); break;
                        case "appid": cfg.AppId = v; break;
                        case "channel": cfg.Channel = v; break;
                        case "key": cfg.Key = v; break;
                        case "enabled": cfg.Enabled = !"false".Equals(v, StringComparison.OrdinalIgnoreCase) && v != "0"; break;
                    }
                }
            }
            catch { }
            return cfg;
        }
    }

    // ---- 与服务端 Contracts 对齐的 DTO（源生成 JSON，AOT 无反射） ----

    public class ManifestFileEntryDto
    {
        public string Path { get; set; } = "";
        public long Size { get; set; }
        public string Sha256 { get; set; } = "";
    }

    public class UpdateManifestDto
    {
        public string AppId { get; set; } = "";
        public string Version { get; set; } = "";
        public string Channel { get; set; } = "";
        public string Os { get; set; }
        public string Arch { get; set; }
        public string Notes { get; set; }
        public bool Mandatory { get; set; }
        public string MinCompatibleVersion { get; set; }
        public DateTime PublishedAtUtc { get; set; }
        public ManifestFileEntryDto[] Files { get; set; } = Array.Empty<ManifestFileEntryDto>();
    }

    public class CheckUpdateDto
    {
        public bool HasUpdate { get; set; }
        public bool Mandatory { get; set; }
        public UpdateManifestDto Manifest { get; set; }
        public string Message { get; set; }
    }

    /// <summary>意见建议反馈提交请求（POST /api/client/feedback）</summary>
    public class FeedbackRequestDto
    {
        public string AppId { get; set; } = "";
        public string Version { get; set; } = "";
        public string Content { get; set; } = "";
        public string Contact { get; set; }
    }

    [JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
    [JsonSerializable(typeof(CheckUpdateDto))]
    [JsonSerializable(typeof(FeedbackRequestDto))]
    public partial class UpdateJsonContext : JsonSerializerContext { }

    /// <summary>
    /// SoftUpdate 更新服务客户端（协议与 SoftUpdate.Server /api/client/* 对齐）：
    /// 检查更新（AES-256-GCM 令牌）→ 逐文件下载 + SHA256 校验。
    /// 仅做「检测 + 下载」，不替换运行中的程序文件。
    /// </summary>
    public class SoftUpdateClient
    {
        private static readonly HttpClient http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        private readonly SoftUpdateConfig cfg;
        private readonly string currentVersion;

        public SoftUpdateClient(SoftUpdateConfig cfg, string currentVersion)
        {
            this.cfg = cfg;
            this.currentVersion = string.IsNullOrWhiteSpace(currentVersion) ? "0.0.0" : currentVersion;
        }

        /// <summary>取程序集版本（csproj Version），无则 0.0.0。</summary>
        public static string GetAssemblyVersion()
        {
            try
            {
                string v = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
                if (string.IsNullOrWhiteSpace(v)) return "0.0.0";
                int plus = v.IndexOf('+'); // 去掉 SourceRevisionId 后缀
                return plus > 0 ? v.Substring(0, plus) : v;
            }
            catch { return "0.0.0"; }
        }

        /// <summary>当前客户端平台（windows/linux/osx），与服务端 Release.Os 取值一致</summary>
        public static string PlatformOs =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "windows"
            : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "osx";

        /// <summary>当前架构（x64/arm64/...），与服务端 Release.Arch 取值一致</summary>
        public static string PlatformArch =>
            RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();

        /// <summary>检查更新。未启用/未配置返回 null；网络或协议异常抛出。
        /// screen 为屏幕分辨率（如 1920x1080，可空），仅用于服务端统计。</summary>
        public async Task<CheckUpdateDto> CheckAsync(CancellationToken ct = default, string screen = null)
        {
            if (!cfg.Enabled || string.IsNullOrWhiteSpace(cfg.Server)) return null;

            string url = cfg.Server + "/api/client/check?appId=" + Uri.EscapeDataString(cfg.AppId)
                + "&channel=" + Uri.EscapeDataString(cfg.Channel)
                + "&version=" + Uri.EscapeDataString(currentVersion)
                + "&os=" + PlatformOs + "&arch=" + PlatformArch
                + "&osDesc=" + Uri.EscapeDataString(RuntimeInformation.OSDescription)
                + (string.IsNullOrWhiteSpace(screen) ? "" : "&screen=" + Uri.EscapeDataString(screen))
                + TokenQuery();

            using (HttpResponseMessage resp = await http.GetAsync(url, ct))
            {
                resp.EnsureSuccessStatusCode();
                string json = await resp.Content.ReadAsStringAsync(ct);
                return JsonSerializer.Deserialize(json, UpdateJsonContext.Default.CheckUpdateDto);
            }
        }

        /// <summary>按清单下载全部文件到 targetDir（含子目录结构），逐文件 SHA256 校验。
        /// 已存在且大小+哈希一致的文件直接跳过（重复下载/断点续传场景秒完成）；
        /// 单 zip 更新包模式（服务端现仅支持单 zip 发布）：下载成功后经 pending-package 标记
        /// 自动清理上一个未安装的更新包，避免运行目录堆积 zip。</summary>
        public async Task DownloadAsync(UpdateManifestDto manifest, string targetDir,
            IProgress<(long done, long total, string file)> progress = null, CancellationToken ct = default)
        {
            Directory.CreateDirectory(targetDir);
            bool singlePackage = manifest.Files.Length == 1
                && manifest.Files[0].Path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
            if (singlePackage)
            {
                CleanupPreviousPackage(targetDir, manifest.Files[0].Path);
            }
            long total = manifest.Files.Sum(f => f.Size);
            long done = 0;
            foreach (var entry in manifest.Files)
            {
                string rel = entry.Path.Replace('\\', '/').TrimStart('/');
                if (rel.Length == 0 || rel.Contains("..")) throw new InvalidOperationException("清单包含非法路径: " + entry.Path);
                string localPath = Path.Combine(targetDir, rel.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(localPath));

                // 已下载且校验一致：直接复用，计入进度
                if (File.Exists(localPath) && new FileInfo(localPath).Length == entry.Size)
                {
                    string existHash;
                    using (Stream s = File.OpenRead(localPath))
                    {
                        existHash = Convert.ToHexString(await SHA256.HashDataAsync(s, ct)).ToLowerInvariant();
                    }
                    if (existHash.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        done += entry.Size;
                        progress?.Report((done, total, entry.Path));
                        continue;
                    }
                }

                string tempPath = localPath + ".part";

                // file 接口按客户端平台匹配发布包（平台限定版本缺 os/arch 会 400）
                string url = cfg.Server + "/api/client/file?appId=" + Uri.EscapeDataString(cfg.AppId)
                    + "&version=" + Uri.EscapeDataString(manifest.Version)
                    + "&path=" + Uri.EscapeDataString(entry.Path)
                    + "&os=" + PlatformOs + "&arch=" + PlatformArch
                    + TokenQuery();

                using (HttpResponseMessage resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct))
                {
                    resp.EnsureSuccessStatusCode();
                    using (Stream remote = await resp.Content.ReadAsStreamAsync(ct))
                    using (Stream local = File.Create(tempPath))
                    {
                        await remote.CopyToAsync(local, ct);
                    }
                }

                string hash;
                using (Stream s = File.OpenRead(tempPath))
                {
                    hash = Convert.ToHexString(await SHA256.HashDataAsync(s, ct)).ToLowerInvariant();
                }
                if (new FileInfo(tempPath).Length != entry.Size
                    || !hash.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(tempPath);
                    throw new InvalidOperationException("文件校验失败（SHA256 不匹配）: " + entry.Path);
                }
                File.Move(tempPath, localPath, true);

                done += entry.Size;
                progress?.Report((done, total, entry.Path));
            }
            if (singlePackage)
            {
                WritePendingMarker(targetDir, manifest.Files[0].Path);
            }
        }

        /// <summary>pending 标记路径（与官方 UpdateManager 一致：{目标目录}/.softupdate/pending-package.txt）</summary>
        private static string PendingMarkerPath(string targetDir)
        {
            return Path.Combine(targetDir, ".softupdate", "pending-package.txt");
        }

        /// <summary>删除上一个未处理的更新包，避免运行目录堆积 zip（清理失败不影响下载）</summary>
        private static void CleanupPreviousPackage(string targetDir, string newPackage)
        {
            try
            {
                string marker = PendingMarkerPath(targetDir);
                if (!File.Exists(marker)) return;
                string previous = File.ReadAllText(marker).Trim();
                if (previous.Length > 0 && previous != newPackage
                    && !previous.Contains("..") && !previous.Contains('/') && !previous.Contains('\\'))
                {
                    string old = Path.Combine(targetDir, previous);
                    if (File.Exists(old)) File.Delete(old);
                }
                File.Delete(marker);
            }
            catch { }
        }

        private static void WritePendingMarker(string targetDir, string package)
        {
            try
            {
                string marker = PendingMarkerPath(targetDir);
                Directory.CreateDirectory(Path.GetDirectoryName(marker));
                File.WriteAllText(marker, package);
            }
            catch { }
        }

        /// <summary>提交意见建议反馈（POST /api/client/feedback，自动携带 appId 与当前版本，联系方式可空）。</summary>
        public async Task SubmitFeedbackAsync(string content, string contact = null, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(content)) throw new ArgumentException("反馈内容不能为空", nameof(content));
            if (!cfg.Enabled || string.IsNullOrWhiteSpace(cfg.Server)) throw new InvalidOperationException("未启用或未配置更新服务（config/update.ini）");

            var dto = new FeedbackRequestDto
            {
                AppId = cfg.AppId,
                Version = currentVersion,
                Content = content.Trim(),
                Contact = string.IsNullOrWhiteSpace(contact) ? null : contact.Trim()
            };
            string token = CreateToken(cfg.Key, cfg.AppId);
            string url = cfg.Server + "/api/client/feedback" + (token == null ? "" : "?token=" + Uri.EscapeDataString(token));
            using (HttpResponseMessage resp = await http.PostAsync(url,
                new StringContent(JsonSerializer.Serialize(dto, UpdateJsonContext.Default.FeedbackRequestDto), Encoding.UTF8, "application/json"), ct))
            {
                resp.EnsureSuccessStatusCode();
            }
        }

        private string TokenQuery()
        {
            string token = CreateToken(cfg.Key, cfg.AppId);
            return token == null ? "" : "&token=" + Uri.EscapeDataString(token);
        }

        /// <summary>AES-256-GCM 令牌：加密 "unix毫秒|appId"，输出 base64url(nonce+密文+tag)。与 ClientToken.Create 一致。</summary>
        public static string CreateToken(string hexKey, string appId)
        {
            if (string.IsNullOrWhiteSpace(hexKey)) return null;
            byte[] key;
            try { key = Convert.FromHexString(hexKey.Trim()); } catch { return null; }
            if (key.Length != 32) return null;

            byte[] plain = Encoding.UTF8.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + "|" + appId);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] cipher = new byte[plain.Length + 16];
            using (var aes = new AesGcm(key, 16))
            {
                aes.Encrypt(nonce, plain, cipher.AsSpan(0, plain.Length), cipher.AsSpan(plain.Length), default);
            }
            return Convert.ToBase64String(nonce.Concat(cipher).ToArray())
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
