using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SPasswordCheckerV2.Data;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Tools;

namespace SPasswordCheckerV2.ViewModels
{
    /// <summary>
    /// 设置窗口（端口配置 + 按服务字典管理）的视图模型，从 MainViewModel 抽出。
    /// 服务列表/内存字典仍由 MainViewModel 持有（扫描任务共用），本类经引用读写；
    /// 字典编辑状态（选中服务/编辑文本/统计）为本窗口私有。
    /// </summary>
    public partial class SetViewModel : ObservableObject
    {
        private readonly MainViewModel main;

        public SetViewModel(MainViewModel main)
        {
            this.main = main;
            // 默认选中第一个服务，字典页直接可编辑（与原 ShowSetWindow 行为一致）
            if (ListServies.Count > 0)
            {
                SelectedDicService = ListServies[0];
            }
        }

        /// <summary>服务列表（与主界面共用同一集合，端口编辑即时生效）</summary>
        public ObservableCollection<Service> ListServies => main.ListServies;

        // ===================== 端口配置 =====================

        //保存端口配置
        [RelayCommand]
        public void SaveSevices()
        {
            List<string> list = new List<string>();
            foreach (Service serv in ListServies)
            {
                list.Add(serv.ServiceName + ":" + String.Join(",", serv.Ports));
            }
            File.WriteAllLines(main.AppBasePath + "/config/service.ini", list.ToArray());
            main.LogFromSet("成功保存配置！");
        }

        // ===================== 字典配置（按服务管理/编辑） =====================

        [ObservableProperty]
        private Service selectedDicService;

        [ObservableProperty]
        private string dicUsernameText = "";

        [ObservableProperty]
        private string dicPasswordText = "";

        [ObservableProperty]
        private string dicStatText = "选择左侧服务后编辑对应字典";

        /// <summary>字典文件名 key：服务名小写并去掉 _ssl（SSL 变体与基础服务共用字典文件，与启动加载逻辑一致）</summary>
        private static string DicKey(string serviceName)
        {
            return serviceName.ToLower().Replace("_ssl", "");
        }

        /// <summary>选中服务变化：从 dic 文件加载字典内容到编辑框</summary>
        partial void OnSelectedDicServiceChanged(Service value)
        {
            if (value == null)
            {
                DicUsernameText = "";
                DicPasswordText = "";
                return;
            }
            string key = DicKey(value.ServiceName);
            DicUsernameText = ReadDicText(key, true);
            DicPasswordText = ReadDicText(key, false);
            UpdateDicStat();
        }

        partial void OnDicUsernameTextChanged(string value)
        {
            UpdateDicStat();
        }

        partial void OnDicPasswordTextChanged(string value)
        {
            UpdateDicStat();
        }

        private string ReadDicText(string key, bool isUsername)
        {
            string path = main.AppBasePath + "/config/dic/dic_" + (isUsername ? "username_" : "password_") + key + ".txt";
            try
            {
                return File.Exists(path) ? File.ReadAllText(path) : "";
            }
            catch (Exception e)
            {
                FileTool.log("读取字典失败 " + path + " " + e.Message);
                return "";
            }
        }

        /// <summary>规范化字典文本：按行拆分、去首尾空白、去空行、去重（保序）</summary>
        private static List<string> NormalizeDic(string text)
        {
            var seen = new HashSet<string>();
            var list = new List<string>();
            foreach (string raw in (text ?? "").Split('\n'))
            {
                string s = raw.Trim();
                if (s.Length > 0 && seen.Add(s))
                {
                    list.Add(s);
                }
            }
            return list;
        }

        private void UpdateDicStat()
        {
            if (SelectedDicService == null)
            {
                DicStatText = "选择左侧服务后编辑对应字典";
                return;
            }
            DicStatText = "用户名 " + NormalizeDic(DicUsernameText).Count + " 条 · 密码 " + NormalizeDic(DicPasswordText).Count + " 条（保存时自动去重）";
        }

        [RelayCommand]
        private void SaveDics()
        {
            if (SelectedDicService == null)
            {
                Msg.Show("请先选择服务！");
                return;
            }
            string key = DicKey(SelectedDicService.ServiceName);
            List<string> users = NormalizeDic(DicUsernameText);
            List<string> passes = NormalizeDic(DicPasswordText);
            try
            {
                string dir = main.AppBasePath + "/config/dic";
                Directory.CreateDirectory(dir);
                File.WriteAllLines(Path.Combine(dir, "dic_username_" + key + ".txt"), users);
                File.WriteAllLines(Path.Combine(dir, "dic_password_" + key + ".txt"), passes);
                // 刷新内存字典：共享同一 key 的所有服务（SSL 变体与基础服务共用文件）
                Dictionary<string, HashSet<string>> listUsernames = main.ServiceUsernamesMap;
                Dictionary<string, HashSet<string>> listPasswords = main.ServicePasswordsMap;
                foreach (string svc in listUsernames.Keys.Where(k => DicKey(k) == key).ToList())
                {
                    listUsernames[svc] = new HashSet<string>(users);
                    listPasswords[svc] = new HashSet<string>(passes);
                }
                // 回显规范化结果（去重去空行后的实际内容）
                DicUsernameText = string.Join("\n", users);
                DicPasswordText = string.Join("\n", passes);
                UpdateDicStat();
                Msg.Show("字典已保存（用户名 " + users.Count + " 条，密码 " + passes.Count + " 条）");
            }
            catch (Exception e)
            {
                Msg.Show("保存字典失败：" + e.Message);
                FileTool.log("保存字典失败 " + key + " " + e.Message + e.StackTrace);
            }
        }

        [RelayCommand]
        private async Task ImportDicUsername()
        {
            await ImportDicInto(true);
        }

        [RelayCommand]
        private async Task ImportDicPassword()
        {
            await ImportDicInto(false);
        }

        /// <summary>从文件导入字典：追加到当前编辑框（保存时统一去重去空行）</summary>
        private async Task ImportDicInto(bool isUsername)
        {
            if (SelectedDicService == null)
            {
                Msg.Show("请先选择服务！");
                return;
            }
            if (main.MainWindow == null)
            {
                return;
            }
            var options = new Avalonia.Platform.Storage.FilePickerOpenOptions
            {
                AllowMultiple = false,
                FileTypeFilter = new[] { new Avalonia.Platform.Storage.FilePickerFileType(isUsername ? "用户名字典" : "密码字典") { Patterns = new[] { "*.txt" } } }
            };
            var files = await main.MainWindow.StorageProvider.OpenFilePickerAsync(options);
            Avalonia.Platform.Storage.IStorageFile file = files != null && files.Count > 0 ? files[0] : null;
            if (file == null)
            {
                return;
            }
            try
            {
                string text = File.ReadAllText(file.Path.LocalPath);
                if (isUsername)
                {
                    DicUsernameText = AppendLines(DicUsernameText, text);
                }
                else
                {
                    DicPasswordText = AppendLines(DicPasswordText, text);
                }
                UpdateDicStat();
            }
            catch (Exception e)
            {
                Msg.Show("导入字典失败：" + e.Message);
            }
        }

        private static string AppendLines(string current, string added)
        {
            string a = (added ?? "").Trim();
            if (a.Length == 0)
            {
                return current;
            }
            string c = (current ?? "").TrimEnd('\n', '\r', ' ');
            return c.Length == 0 ? a : c + "\n" + a;
        }
    }
}
