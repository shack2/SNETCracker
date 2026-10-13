using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.IO;
using System.Threading.Tasks;
using Tools;

namespace SPasswordCheckerV2.ViewModels
{
    /// <summary>
    /// 更新窗口的数据对象（对接 SoftUpdate 更新服务）：
    /// 检查更新 → 用户确认 → 下载 zip 更新包到软件运行目录（SHA256 校验 + 已有包哈希复用，
    /// 自动清理上一个未安装的更新包；不替换运行中文件）。
    /// </summary>
    internal partial class UpdateViewModel : ObservableObject
    {
        /// <summary>历史版本号（关于/版本菜单展示用）</summary>
        public static int versionInfo = 20220720;

        private UpdateManifestDto manifest;
        /// <summary>启动自动检测命中更新时置 true：窗口打开后直接开始下载</summary>
        public bool AutoDownload;
        private string lastDir;

        /// <summary>当前程序版本</summary>
        [ObservableProperty]
        private string currentVersion = "-";

        /// <summary>当前服务器上最新版本</summary>
        [ObservableProperty]
        private string newVersionText = "-";

        /// <summary>更新说明</summary>
        [ObservableProperty]
        private string notesText = "";

        /// <summary>文件数与总大小</summary>
        [ObservableProperty]
        private string fileInfoText = "";

        /// <summary>下载进度</summary>
        [ObservableProperty]
        private double downLoadProcess = 0;

        /// <summary>下载数量与总量的比例</summary>
        [ObservableProperty]
        private string downLoadRatio = "";

        [ObservableProperty]
        private string info = "正在检查更新...";

        /// <summary>「下载更新」可用：已查到更新且未在下载中</summary>
        [ObservableProperty]
        private bool canDownload = false;

        /// <summary>「打开目录」可用：下载完成后</summary>
        [ObservableProperty]
        private bool canOpenDir = false;

        /// <summary>由启动自动检测传入已查到的更新清单，窗口直接下载</summary>
        public void SetManifest(UpdateManifestDto m)
        {
            CurrentVersion = SoftUpdateClient.GetAssemblyVersion();
            ApplyManifest(m);
            AutoDownload = true;
        }

        private void ApplyManifest(UpdateManifestDto m)
        {
            manifest = m;
            NewVersionText = m.Version;
            NotesText = string.IsNullOrWhiteSpace(m.Notes) ? "（无更新说明）" : m.Notes;
            long total = 0;
            foreach (var f in m.Files) total += f.Size;
            FileInfoText = m.Files.Length + " 个文件，共 " + (total / 1024.0 / 1024).ToString("0.0") + " MB";
            Info = "发现新版本，点击「下载更新」";
            CanDownload = true;
        }

        private static SoftUpdateClient NewClient()
        {
            var cfg = SoftUpdateConfig.Load(AppContext.BaseDirectory + "/config/update.ini");
            return new SoftUpdateClient(cfg, SoftUpdateClient.GetAssemblyVersion());
        }

        [RelayCommand]
        public void UpdateData()
        {
            if (manifest == null)
            {
                Info = "未发现可下载的更新！";
                return;
            }
            CanDownload = false;
            // 新版更新方式：单个 zip 更新包直接下载到软件运行目录（已存在且哈希一致会秒过）
            string targetDir = AppContext.BaseDirectory;
            Task.Run(async () =>
            {
                try
                {
                    Info = "正在下载...";
                    var progress = new Progress<(long done, long total, string file)>(p =>
                    {
                        double radio = p.total > 0 ? Math.Floor(p.done * 100.0 / p.total) : 0;
                        DownLoadProcess = radio;
                        DownLoadRatio = radio + "%（" + p.file + "）";
                    });
                    await NewClient().DownloadAsync(manifest, targetDir, progress);
                    DownLoadProcess = 100;
                    DownLoadRatio = "100%";
                    lastDir = targetDir;
                    Info = "下载完成，更新包在软件运行目录：" + (manifest.Files.Length > 0 ? manifest.Files[0].Path : targetDir);
                    CanOpenDir = true;
                }
                catch (Exception e)
                {
                    Info = "更新异常！" + e.Message;
                    CanDownload = true;
                }
            });
        }

        [RelayCommand]
        public void GetNewVersion()
        {
            Task.Run(async () =>
            {
                try
                {
                    CanDownload = false;
                    Info = "正在检查更新...";
                    CurrentVersion = SoftUpdateClient.GetAssemblyVersion();
                    var result = await NewClient().CheckAsync();
                    if (result == null)
                    {
                        Info = "未启用自动更新检测（config/update.ini）";
                        return;
                    }
                    if (result.HasUpdate && result.Manifest != null)
                    {
                        ApplyManifest(result.Manifest);
                    }
                    else
                    {
                        NewVersionText = CurrentVersion;
                        NotesText = "";
                        FileInfoText = "";
                        Info = string.IsNullOrWhiteSpace(result.Message) ? "当前已是最新版本！" : result.Message;
                    }
                }
                catch (Exception e)
                {
                    Info = "更新检测异常！" + e.Message;
                }
            });
        }

        /// <summary>打开下载目录</summary>
        [RelayCommand]
        private void OpenDir()
        {
            try
            {
                if (lastDir != null && Directory.Exists(lastDir) && OperatingSystem.IsWindows())
                {
                    System.Diagnostics.Process.Start("explorer.exe", "\"" + lastDir + "\"");
                }
            }
            catch { }
        }

        /// <summary>是否关闭更新程序</summary>
        [RelayCommand]
        private async Task CancelUpdate(object window)
        {
            var w = window as Avalonia.Controls.Window;
            if (w == null) return;
            bool confirmed = await Msg.ConfirmAsync("您确定取消更新吗？", "提示");
            if (confirmed)
            {
                w.Close();
            }
        }
    }
}
