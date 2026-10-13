using Avalonia.Input.Platform;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SNETCracker.Checker;
using SNETCracker.Except;
using SPasswordCheckerV2.Data;
using SPasswordCheckerV2.Views;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Tools;
using Service = SPasswordCheckerV2.Data.Service;

namespace SPasswordCheckerV2.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        public static string ThemeName = "Dark";

        public MainWindow MainWindow
        {
            get { return _mainWindow; }
            set { _mainWindow = value; }
        }
        private MainWindow _mainWindow;

        private Dictionary<string, HashSet<string>> listUsernames = new Dictionary<string, HashSet<string>>();

        private Dictionary<string, HashSet<string>> listPasswords = new Dictionary<string, HashSet<string>>();

        private HashSet<string> clistUsernames = new HashSet<string>();
        private HashSet<string> clistPasswords = new HashSet<string>();
        private List<string> targetList = new List<string>();

        /// <summary>扫描引擎：协议检测 + 端口探测 + 并发调度全部在 shack2.pass.checker 库；
        /// 进度/状态经 Engine.* 读取（UpdateStatus 与 TestRun 断言共用）</summary>
        public readonly SNETCracker.Engine.ScanEngine Engine = new SNETCracker.Engine.ScanEngine();

        private string BasePath = AppContext.BaseDirectory;

        // ---- 设置窗口（SetViewModel）内部访问口：服务字典/基础路径/日志仍由本类持有 ----
        internal string AppBasePath => BasePath;
        internal Dictionary<string, HashSet<string>> ServiceUsernamesMap => listUsernames;
        internal Dictionary<string, HashSet<string>> ServicePasswordsMap => listPasswords;
        internal void LogFromSet(string msg)
        {
            LogMessage(msg);
        }
        private System.Diagnostics.Stopwatch mainSw = new System.Diagnostics.Stopwatch();
        private int isRun = 0;

        /// <summary>当前检查任务的取消令牌；Stop() 通过它停止枚举新任务</summary>
        private CancellationTokenSource crackCts;

        //结果表格选中项（由视图 SelectionChanged 回写）
        public IList SelectedCheckResults { get; set; }

        public MainViewModel()
        {
            HashSet<string> list_services = FileTool.readFileToList(BasePath + "/config/service.ini");
            ListServies = new ObservableCollection<Service>();
            foreach (string service in list_services)
            {
                string[] strs = service.Split(':');
                int[] ports = Array.ConvertAll(strs[1].Split(','), int.Parse);
                var sv = new Service(strs[0], ports);
                ListServies.Add(sv);
                sv.PropertyChanged += (s, e) =>
                {
                    if (e.PropertyName == nameof(Service.IsChecked))
                    {
                        UpdateSelectedCountText();
                    }
                };
                listUsernames.Add(strs[0], FileTool.readFileToList(BasePath + "/config/dic/dic_username_" + strs[0].ToLower().Replace("_ssl", "") + ".txt"));
                listPasswords.Add(strs[0], FileTool.readFileToList(BasePath + "/config/dic/dic_password_" + strs[0].ToLower().Replace("_ssl", "") + ".txt"));
            }
            UpdateSelectedCountText();
            ListCheckResult = new ObservableCollection<CheckResult>();
            ListCheckResult.CollectionChanged += OnListCheckResultChanged;
            ResultsView = new ObservableCollection<CheckResult>();
            // 启动时恢复上次设置（主题/参数/勾选服务）
            LoadSettings();
        }

        private const string SettingFileName = "/config/setting.ini";
        private bool loadingSettings;

        /// <summary>U3 用户偏好持久化：主题 + 扫描参数 + 勾选服务，key=value 逐行存 setting.ini</summary>
        private void LoadSettings()
        {
            try
            {
                string settingFile = BasePath + SettingFileName;
                if (!File.Exists(settingFile))
                {
                    return;
                }
                loadingSettings = true;
                var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string line in File.ReadAllLines(settingFile))
                {
                    int eq = line.IndexOf('=');
                    if (eq > 0)
                    {
                        map[line.Substring(0, eq).Trim()] = line.Substring(eq + 1).Trim();
                    }
                }
                if (map.TryGetValue("ThemeName", out string theme) && (theme == "Light" || theme == "Dark"))
                {
                    SetTheme(theme);
                }
                if (map.TryGetValue("Timeout", out string t) && int.TryParse(t, out int tv) && tv > 0)
                {
                    Timeout = tv;
                }
                if (map.TryGetValue("ThreadCount", out string tc) && int.TryParse(tc, out int tcv) && tcv > 0)
                {
                    ThreadCount = tcv;
                }
                if (map.TryGetValue("RetryCount", out string rc) && int.TryParse(rc, out int rcv) && rcv >= 0)
                {
                    RetryCount = rcv;
                }
                if (map.TryGetValue("IsCheckPort", out string icp))
                {
                    IsCheckPort = icp == "1" || icp.Equals("true", StringComparison.OrdinalIgnoreCase);
                }
                if (map.TryGetValue("IsAutoSelectDic", out string iad))
                {
                    IsAutoSelectDic = iad == "1" || iad.Equals("true", StringComparison.OrdinalIgnoreCase);
                }
                if (map.TryGetValue("SuccessOneIsContinue", out string soc))
                {
                    SuccessOneIsContinue = soc == "1" || soc.Equals("true", StringComparison.OrdinalIgnoreCase);
                }
                if (map.TryGetValue("UsernameExt", out string ue))
                {
                    UsernameExt = ue;
                }
                if (map.TryGetValue("HostFailFast", out string hff))
                {
                    HostFailFast = hff == "1" || hff.Equals("true", StringComparison.OrdinalIgnoreCase);
                }
                if (map.TryGetValue("PerHostLimit", out string phl) && int.TryParse(phl, out int phlv) && phlv >= 0)
                {
                    PerHostLimit = phlv;
                }
                if (map.TryGetValue("LockoutFailLimit", out string lfl) && int.TryParse(lfl, out int lflv) && lflv > 0)
                {
                    LockoutFailLimit = lflv;
                }
                if (map.TryGetValue("CheckedServices", out string cs))
                {
                    var wanted = new HashSet<string>(cs.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);
                    foreach (Service sv in ListServies)
                    {
                        sv.IsChecked = wanted.Contains(sv.ServiceName);
                    }
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                loadingSettings = false;
            }
        }

        /// <summary>保存当前偏好（主题在 SetTheme 时保存；参数/勾选服务在 StartCheck 时保存）</summary>
        private void SaveSettings()
        {
            if (loadingSettings)
            {
                return;
            }
            try
            {
                string checkedNames = string.Join(",", ListServies.Where(s => s.IsChecked).Select(s => s.ServiceName));
                var sb = new System.Text.StringBuilder();
                sb.Append("ThemeName=").Append(IsDarkTheme ? "Dark" : "Light").Append('\n');
                sb.Append("Timeout=").Append(Timeout).Append('\n');
                sb.Append("ThreadCount=").Append(ThreadCount).Append('\n');
                sb.Append("RetryCount=").Append(RetryCount).Append('\n');
                sb.Append("IsCheckPort=").Append(IsCheckPort ? "1" : "0").Append('\n');
                sb.Append("IsAutoSelectDic=").Append(IsAutoSelectDic ? "1" : "0").Append('\n');
                sb.Append("SuccessOneIsContinue=").Append(SuccessOneIsContinue ? "1" : "0").Append('\n');
                sb.Append("UsernameExt=").Append(UsernameExt ?? "").Append('\n');
                sb.Append("HostFailFast=").Append(HostFailFast ? "1" : "0").Append('\n');
                sb.Append("PerHostLimit=").Append(PerHostLimit).Append('\n');
                sb.Append("LockoutFailLimit=").Append(LockoutFailLimit).Append('\n');
                sb.Append("CheckedServices=").Append(checkedNames).Append('\n');
                File.WriteAllText(BasePath + SettingFileName, sb.ToString());
            }
            catch (Exception)
            {
            }
        }

        /// <summary>防锁定熔断阈值见 ScanOptions.LockoutFailLimit（引擎持有判重/拉黑/熔断状态）</summary>
        [ObservableProperty]
        private string scanPortProgressText = "—";

        public int TargetCount = 0;

        [ObservableProperty]
        private double progressValue = 0;

        public int ListBoxSelectCount { get; set; }

        [ObservableProperty]
        private ObservableCollection<CheckResult> listCheckResult;

        /// <summary>结果筛选关键字（命中 IP/服务/端口/账户/密码/Banner 任意字段即保留）</summary>
        [ObservableProperty]
        private string resultFilter = "";

        partial void OnResultFilterChanged(string value) => RefreshResultsView();

        /// <summary>结果表的筛选视图：表格显示与导出/复制共用同一份过滤结果（手动同步，替代 DataGridCollectionView）</summary>
        public ObservableCollection<CheckResult> ResultsView { get; private set; }

        /// <summary>主结果集增删时同步进筛选视图（按当前筛选条件过滤）</summary>
        private void OnListCheckResultChanged(object sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
        {
            HasResult = ListCheckResult.Count > 0;
            if (e.Action == System.Collections.Specialized.NotifyCollectionChangedAction.Reset)
            {
                RefreshResultsView();
                return;
            }
            if (e.OldItems != null)
            {
                foreach (CheckResult cr in e.OldItems)
                {
                    ResultsView.Remove(cr);
                }
            }
            if (e.NewItems != null)
            {
                foreach (CheckResult cr in e.NewItems)
                {
                    if (ResultFilterMatch(cr))
                    {
                        ResultsView.Add(cr);
                    }
                }
            }
        }

        /// <summary>筛选条件变化时整体重建筛选视图</summary>
        private void RefreshResultsView()
        {
            if (ResultsView == null)
            {
                return;
            }
            ResultsView.Clear();
            foreach (CheckResult cr in ListCheckResult)
            {
                if (ResultFilterMatch(cr))
                {
                    ResultsView.Add(cr);
                }
            }
        }

        private bool ResultFilterMatch(object o)
        {
            string f = ResultFilter?.Trim();
            if (string.IsNullOrEmpty(f) || o is not CheckResult cr)
            {
                return true;
            }
            return Hit(cr.IP) || Hit(cr.ServiceName) || Hit(cr.Username)
                || Hit(cr.Password) || Hit(cr.Banner) || Hit(cr.Port.ToString());
            bool Hit(string s) => s != null && s.Contains(f, StringComparison.OrdinalIgnoreCase);
        }

        [ObservableProperty]
        private ObservableCollection<Service> listServies;

        /// <summary>当前勾选的服务</summary>
        public IEnumerable<Service> SelectedServices
        {
            get { return ListServies.Where(s => s.IsChecked).ToList(); }
        }

        [ObservableProperty]
        private string txtTarget = "";

        [ObservableProperty]
        private bool successOneIsContinue;

        [ObservableProperty]
        private int timeout = 15;

        [ObservableProperty]
        private bool isCheckPort = true;

        [ObservableProperty]
        private string username = "";

        [ObservableProperty]
        private string usernameExt = "";

        [ObservableProperty]
        private int threadCount = 30;

        /// <summary>认证并发上限选项。认证是纯阻塞 I/O，由 Parallel.ForEachAsync 限并发执行，200 并发开销可控</summary>
        public int[] ThreadCountOptions { get; } = new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 50, 75, 100, 150, 200 };

        public int[] TimeoutOptions { get; } = new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 50, 60 };

        [ObservableProperty]
        private string password = "";

        [ObservableProperty]
        private bool isAutoSelectDic = true;

        [ObservableProperty]
        private int retryCount = 0;

        /// <summary>死主机短路：端口探测连续纯超时判死并跳过该主机剩余端口（默认开）</summary>
        [ObservableProperty]
        private bool hostFailFast = true;

        /// <summary>单主机认证并发上限（0=不限）</summary>
        [ObservableProperty]
        private int perHostLimit = 0;

        /// <summary>防账号锁定熔断阈值：同一账号连续失败达此值跳过剩余密码</summary>
        [ObservableProperty]
        private int lockoutFailLimit = 50;

        [ObservableProperty]
        private string checkerTaskInfo = "";

        [ObservableProperty]
        private string runThread = "0/0";

        [ObservableProperty]
        private string useTime = "0";

        [ObservableProperty]
        private string txtLogs = "";

        [ObservableProperty]
        private int successCount = 0;

        /// <summary>检测结果是否存在（用于空状态展示）</summary>
        [ObservableProperty]
        private bool hasResult;

        /// <summary>当前是否正在检查（用于按钮/状态联动）</summary>
        [ObservableProperty]
        private bool isRunning;

        /// <summary>左侧服务已选数量文案</summary>
        [ObservableProperty]
        private string selectedCountText = "";

        /// <summary>日志面板是否展开</summary>
        [ObservableProperty]
        private bool isLogExpanded = true;

        private void UpdateSelectedCountText()
        {
            int n = ListServies.Count(s => s.IsChecked);
            SelectedCountText = $"已选 {n}/{ListServies.Count}";
        }

        private Avalonia.Threading.DispatcherTimer UITimer = new Avalonia.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };

        private void SetTimer()
        {
            UITimer.Tick += (s, e) => UpdateStatus();
        }

        private void InitParams()
        {
            ProgressValue = 0;
        }

        private void UpdateStatus()
        {
            FlushLogs(); // 每秒定时器驱动：批量刷新日志
            SuccessCount = Engine.checkSuccessCount;
            RunThread = Engine.activeAuthCount + "/" + ThreadCount;
            CheckerTaskInfo = Engine.checkSumCount + "/" + Engine.allCrackCount;
            double pv = 0;
            if (Engine.checkSumCount != 0)
            {
                pv = Math.Floor((Engine.allCrackCount * 100) / (double)Engine.checkSumCount);
            }
            ProgressValue = pv;
            long scanTotal = Engine.scanPortTaskTotal;
            ScanPortProgressText = scanTotal > 0
                ? (Engine.scanPortTaskSum > 0 ? $"已探测 {scanTotal - Engine.scanPortTaskSum}/{scanTotal}" : $"完成 {scanTotal}")
                : "—";
            UseTime = Math.Floor((decimal)mainSw.ElapsedMilliseconds / 1000) + "";
        }

        [RelayCommand]
        private async Task ImportUserNameDic()
        {
            var file = await PickOpenFileAsync("用户名字典", "txt");
            if (file != null)
            {
                string path = file.Path.LocalPath;
                Username = path;
                IsAutoSelectDic = false;
                clistUsernames.Clear();
                clistUsernames = FileTool.readFileToList(path);
            }
        }

        [RelayCommand]
        private async Task ImportPasswordDic()
        {
            var file = await PickOpenFileAsync("密码", "txt");
            if (file != null)
            {
                string path = file.Path.LocalPath;
                Password = path;
                IsAutoSelectDic = false;
                clistPasswords.Clear();
                var list = await Task<List<string>>.Run(() =>
                {
                    return FileTool.readFileToList(path).ToList();
                });
                clistPasswords = new HashSet<string>(list);
            }
        }

        [RelayCommand]
        private async Task ImportTarget()
        {
            var file = await PickOpenFileAsync("目标列表", "txt");
            if (file != null)
            {
                HashSet<string> list = await Task<HashSet<string>>.Run(() =>
                {
                    return FileTool.readFileToList(file.Path.LocalPath);
                });
                TxtTarget = "";
                StringBuilder sb = new StringBuilder();
                foreach (string line in list)
                {
                    if (SNETCracker.Engine.TargetParser.IsValidLine(line))
                    {
                        sb.Append(line.Trim() + "\n");
                    }
                }
                if (sb.Length > 0)
                {
                    TxtTarget = sb.Remove(sb.Length - 1, 1).ToString();
                }
            }
        }

        private async Task<Avalonia.Platform.Storage.IStorageFile> PickOpenFileAsync(string name, string ext)
        {
            if (MainWindow == null) return null;
            var options = new Avalonia.Platform.Storage.FilePickerOpenOptions
            {
                AllowMultiple = false,
                FileTypeFilter = new[] { new Avalonia.Platform.Storage.FilePickerFileType(name) { Patterns = new[] { "*." + ext } } }
            };
            var files = await MainWindow.StorageProvider.OpenFilePickerAsync(options);
            return files.Count > 0 ? files[0] : null;
        }

        /// <summary>当前主题是否为深色（驱动主题按钮图标切换）</summary>
        [ObservableProperty]
        private bool isDarkTheme = true;

        [RelayCommand]
        public void SetTheme(string theme)
        {
            ThemeName = theme;
            IsDarkTheme = theme != "Light";
            if (Avalonia.Application.Current != null)
            {
                Avalonia.Application.Current.RequestedThemeVariant = theme == "Light"
                    ? Avalonia.Styling.ThemeVariant.Light
                    : Avalonia.Styling.ThemeVariant.Dark;
            }
            // 持久化主题选择，下次启动时恢复
            SaveSettings();
        }

        [RelayCommand]
        public void ToggleTheme()
        {
            SetTheme(IsDarkTheme ? "Light" : "Dark");
        }

        [RelayCommand]
        public void Stop()
        {
            // 取消当前任务：停止枚举新认证任务，在途认证走完各自的超时后自然结束；
            // 下次 StartCheck 会用新的 CancellationTokenSource，互不影响
            crackCts?.Cancel();
        }

        [RelayCommand]
        public void StartCheck()
        {
            if (isRun == 0)
            {
                isRun = 1;
                IsRunning = true;
                SaveSettings(); // 开始时固化当前参数/勾选服务，下次启动恢复
                Task.Run(() =>
                {
                    try
                    {
                        CheckPass();
                    }
                    catch (Exception e)
                    {
                        // 调度层异常不能无声吞掉：写日志便于排障
                        LogMessage("任务调度异常！" + e.Message);
                        FileTool.log("CheckPass 异常 " + e.Message + e.StackTrace);
                    }
                    finally
                    {
                        IsRunning = false;
                        isRun = 0; // 归位必须在 finally 中，防重入才真正生效
                    }
                });
            }
            else
            {
                Msg.Show("上一次任务还在运行！");
            }
        }

        [RelayCommand]
        public void DeleteSelectedCheckResult()
        {
            if (SelectedCheckResults == null) return;
            List<CheckResult> removeList = new List<CheckResult>();
            foreach (var item in SelectedCheckResults)
            {
                removeList.Add((CheckResult)item);
            }
            //不能在上面遍历时删除，否则删除多个会导致选中集合发生修改，报错
            foreach (var item in removeList)
            {
                ListCheckResult.Remove(item);
            }
            removeList.Clear();
        }

        [RelayCommand]
        public async Task ExportCheckResult()
        {
            // 导出与表格一致：应用当前筛选条件后的结果集
            List<CheckResult> rows = ResultsView.Cast<CheckResult>().ToList();
            if (rows.Count > 0)
            {
                if (MainWindow == null) return;
                var options = new Avalonia.Platform.Storage.FilePickerSaveOptions
                {
                    FileTypeChoices = new[] { new Avalonia.Platform.Storage.FilePickerFileType("导出") { Patterns = new[] { "*.txt" } } }
                };
                var file = await MainWindow.StorageProvider.SaveFilePickerAsync(options);
                if (file != null)
                {
                    string path = file.Path.LocalPath;
                    await Task.Run(() =>
                    {
                        // 一次打开批量写：替代逐行 AppendLogToFile（每行开关文件+加锁，大结果集导出慢）
                        using (var sw = new StreamWriter(path, false, System.Text.Encoding.UTF8))
                        {
                            foreach (CheckResult cr in rows)
                            {
                                sw.WriteLine(GetStringByResult(cr));
                            }
                        }
                    });
                    Msg.Show($"导出成功，共 {rows.Count} 条！");
                }
            }
            else
            {
                Msg.Show(ListCheckResult.Count > 0 ? "当前筛选条件下无结果！" : "暂无检测结果！");
            }
        }

        private string GetStringByResult(CheckResult cr)
        {
            return cr.Index + "----" + cr.ServiceName + "----" + cr.IP + "----" + cr.Port + "----" + cr.Username + "----" + cr.Password;
        }

        // 端口配置/字典配置已抽到 SetViewModel（设置窗口 DataContext）

        [RelayCommand]
        public async Task CopyService()
        {
            StringBuilder sb = new StringBuilder();
            // 复制与表格一致：应用当前筛选条件后的结果集
            foreach (CheckResult cr in ResultsView.Cast<CheckResult>())
            {
                sb.Append(GetStringByResult(cr));
            }
            if (MainWindow?.Clipboard != null)
            {
                await MainWindow.Clipboard.SetTextAsync(sb.ToString());
            }
            Msg.Show("复制成功！");
        }

        public void CheckPass()
        {
            // 每次任务独立取消令牌：Stop() 只影响当前任务，下次开始用新令牌
            crackCts = new CancellationTokenSource();
            CancellationToken ct = crackCts.Token;
            mainSw.Restart();
            SetTimer();
            UITimer.Start();
            List<Service> selectedServices = SelectedServices.ToList();
            ListBoxSelectCount = selectedServices.Count;
            if (ListBoxSelectCount == 0)
            {
                Msg.Show("请选择需要检查的服务！");
            }
            else
            {
                InitParams();
                if (CheckTarget() && CheckDic())
                {
                    try
                    {
                        Engine.LogHandler = LogMessage;
                        Engine.FoundHandler = addResultMulThread;
                        var req = new SNETCracker.Engine.ScanRequest
                        {
                            Targets = targetList,
                            Services = selectedServices.Select(sv => new SNETCracker.Engine.ScanService(sv.ServiceName, sv.Ports)).ToList(),
                            ServiceUsernames = listUsernames,
                            ServicePasswords = listPasswords,
                            Usernames = clistUsernames,
                            Passwords = clistPasswords
                        };
                        var opt = new SNETCracker.Engine.ScanOptions
                        {
                            Threads = ThreadCount,
                            TimeoutSec = Timeout,
                            RetryCount = RetryCount,
                            PortScan = IsCheckPort,
                            AutoDic = IsAutoSelectDic,
                            UsernameExt = UsernameExt ?? "",
                            StopOnSuccess = SuccessOneIsContinue,
                            HostFailFast = HostFailFast,
                            PerHostLimit = PerHostLimit,
                            LockoutFailLimit = LockoutFailLimit,
                            LogDir = BasePath + "/logs"
                        };
                        Engine.Run(req, opt, ct);
                    }
                    catch (OperationCanceledException)
                    {
                        LogMessage("任务已停止！");
                    }
                }
                if (!ct.IsCancellationRequested)
                {
                    LogMessage("检查完成！");
                }
            }
            UITimer.Stop();
            UpdateStatus();
            mainSw.Stop();
        }

        /// <summary>同步端口探测（供测试/单点调用）；批量扫描由引擎执行</summary>
        public void ScanPort(string ip, string serviceName, int port)
        {
            Engine.LogHandler = LogMessage;
            Engine.ScanPort(ip, serviceName, port, Timeout);
        }

        [RelayCommand]
        public void ShowSetWindow()
        {
            // 设置窗口有独立视图模型（端口/字典配置逻辑在 SetViewModel）；
            // 构造时默认选中第一个服务，字典页直接可编辑
            SetWindow sw = new SetWindow();
            sw.DataContext = new SetViewModel(this);
            sw.ShowDialog(MainWindow);
        }

        [RelayCommand]
        public void CheckVersion()
        {
            UpdateWindow uw = new UpdateWindow();
            var uvm = new UpdateViewModel();
            uw.DataContext = uvm;
            uw.ShowDialog(MainWindow);
        }

        /// <summary>启动自动检测更新：有新版时提示是否下载（下载到运行目录 update\版本号\）</summary>
        [RelayCommand]
        public void GetNewVersion()
        {
            Task.Run(async () =>
            {
                try
                {
                    var cfg = SoftUpdateConfig.Load(BasePath + "/config/update.ini");
                    if (!cfg.Enabled) return;
                    var client = new SoftUpdateClient(cfg, SoftUpdateClient.GetAssemblyVersion());
                    var result = await client.CheckAsync();
                    if (result == null || !result.HasUpdate || result.Manifest == null) return;

                    var manifest = result.Manifest;
                    LogMessage("发现新版本：" + manifest.Version + "（当前 " + SoftUpdateClient.GetAssemblyVersion() + "）");
                    string notes = string.IsNullOrWhiteSpace(manifest.Notes) ? "" : "\n\n更新说明：\n" + manifest.Notes;
                    bool ok = await Msg.ConfirmAsync(
                        "发现新版本 " + manifest.Version + notes + "\n\n是否下载更新？（下载到软件运行目录）", "版本更新");
                    if (!ok) return;

                    Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                    {
                        UpdateWindow uw = new UpdateWindow();
                        var uvm = new UpdateViewModel();
                        uvm.SetManifest(manifest);
                        uw.DataContext = uvm;
                        uw.Show(MainWindow);
                    });
                }
                catch (Exception e)
                {
                    LogMessage("自动检测更新异常：" + e.Message);
                }
            });
        }

        [RelayCommand]
        public void About()
        {
            Msg.Show("此工具为常见服务弱口令检查工具，提供给企业、运维人员、安全工程师进行企业内部弱口令检查使用，请勿非法使用！");
        }

        [RelayCommand]
        public void Version()
        {
            Msg.Show("超级弱口令检查工具V2.0 " + UpdateViewModel.versionInfo);
        }

        [RelayCommand]
        public void Feed()
        {
            // 在线反馈（提交到更新服务 /api/client/feedback），服务不可用时窗口内提示邮箱渠道
            FeedbackWindow fw = new FeedbackWindow();
            if (MainWindow != null)
            {
                fw.ShowDialog(MainWindow);
            }
            else
            {
                fw.Show();
            }
        }

        /// <summary>待刷新日志队列：LogMessage 只入队，由 UI 定时器每秒批量合并刷新，避免每条日志都触发 TextBox 全文重排</summary>
        private readonly ConcurrentQueue<string> pendingLogs = new ConcurrentQueue<string>();

        private void LogMessage(string log)
        {
            pendingLogs.Enqueue(log);
            if (!UITimer.IsEnabled)
            {
                // 非检查期间（定时器未运行）立即刷新，避免日志滞留
                FlushLogs();
            }
        }

        /// <summary>把队列里的日志合并为一次 UI 更新（最多每秒一次）</summary>
        private void FlushLogs()
        {
            if (pendingLogs.IsEmpty)
            {
                return;
            }
            var sb = new StringBuilder();
            while (pendingLogs.TryDequeue(out string line))
            {
                sb.Append(line).Append('\n');
            }
            string batch = sb.ToString();
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                TxtLogs += batch;
                // 日志封顶：字符串 += 是整串复制，不封顶长时间运行会退化为 O(n²) 拖垮 UI
                const int MaxLogChars = 200000;
                if (TxtLogs.Length > MaxLogChars)
                {
                    string s = TxtLogs;
                    int cut = s.IndexOf('\n', s.Length - MaxLogChars / 2);
                    TxtLogs = cut >= 0 ? s.Substring(cut + 1) : s.Substring(s.Length - MaxLogChars / 2);
                }
            });
        }

        private bool CheckTarget()
        {
            // Trim 由 TargetParser 内部处理（去 CRLF/空格、空行跳过）
            targetList = SNETCracker.Engine.TargetParser.ParseLines(TxtTarget.Split('\n'), LogMessage);

            if (this.targetList.Count <= 0)
            {
                Msg.Show("目标格式错误！\r\n格式示例：\r\n192.168.1.1\r\nwww.baidu.com\r\n192.168.1.1-192.168.1.200\r\n192.168.1.0/24");
                return false;
            }
            return true;
        }

        //加载自定义字典
        public bool CheckDic()
        {
            //加载自定义字典字典
            if (!IsAutoSelectDic)
            {
                // 输入框二义性解析：文本是存在的文件路径 → 按字典读取；否则 → 单个用户名/密码
                clistUsernames = LoadDicOrSingle(Username);
                clistPasswords = LoadDicOrSingle(Password);

                if (this.clistUsernames.Count <= 0)
                {
                    Msg.Show("请设置用户名或自动选择用户名字典！");
                    return false;
                }
                if (clistPasswords.Count <= 0)
                {
                    Msg.Show("请设置密码或自动选择密码字典！");
                    return false;
                }
            }
            return true;
        }

        /// <summary>存在的文件路径 → 读字典；否则非空文本 → 单个值；空 → 空集合（实现已迁入引擎库 DicLoader）</summary>
        internal static HashSet<string> LoadDicOrSingle(string text)
        {
            return SNETCracker.Engine.DicLoader.LoadDicOrSingle(text);
        }

        public void addResultMulThread(CheckResult cr)
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                ListCheckResult.Add(cr);
            });
        }
    }
}
