using Amib.Threading;
using Microsoft.Win32;
using Mono.Security.Cryptography;
using MyRDP;
using SNETCracker.Model;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Tools;

namespace SNETCracker
{
    public partial class Main : Form
    {

        private HashSet<string> list_username = new HashSet<string>();
        private HashSet<string> list_password = new HashSet<string>();
        private HashSet<string> list_target = new HashSet<string>();
        private HashSet<string> list_import_target = new HashSet<string>();
        private HashSet<string> list_ip_break = new HashSet<string>();
        private HashSet<string> list_ip_user_break = new HashSet<string>();
        private HashSet<string> list_success_username = new HashSet<string>();
        private int runTime = 0;
        private int retryCount = 0;
        private int maxThread = 50;
        private int timeOut = 5;

        private Boolean crackerOneCount = true;//只检查一个账户
        public int successCount = 0;
        public long creackerSumCount = 0;
        public long allCrackCount = 0;
        private Boolean notAutoSelectDic = true;
        public string[] servicesName = { };
        public string[] servicesPort = { };

        public long scanPortsSumCount = 0;

        private Dictionary<string, ServiceModel> services = new Dictionary<string, ServiceModel>();//服务列表
        private Dictionary<string, HashSet<string>> dics = new Dictionary<string, HashSet<string>>();//字典列表
        public ConcurrentBag<string> list_cracker = new ConcurrentBag<string>();
        public void initServices()
        {
            try
            {

                string servicesNamesStr = FileTool.readFileToString(Directory.GetCurrentDirectory() + "/config/servicesnames.txt");
                string servicesPortsStr = FileTool.readFileToString(Directory.GetCurrentDirectory() + "/config/servicesports.txt");
                this.servicesName = servicesNamesStr.Split(':');
                this.servicesPort = servicesPortsStr.Split(':');
            }
            catch (Exception e)
            {

                LogWarning("加载检查服务配置发生异常！" + e.Message);
            }
            services.Clear();
            for (int i = 0; i < servicesName.Length; i++)
            {
                ServiceModel sm = new ServiceModel();
                sm.Name = servicesName[i];
                sm.Port = servicesPort[i];
                //SSL和非SSL采用一个字典
                string dicname = sm.Name.ToLower().Replace("_ssl", "");
                sm.DicUserNamePath = "/dic/dic_username_" + dicname + ".txt";
                sm.DicPasswordPath = "/dic/dic_password_" + dicname + ".txt";
                services.Add(sm.Name, sm);
            }
        }

        public Main()
        {
            InitializeComponent();
            Form.CheckForIllegalCrossThreadCalls = false;
        }
        public delegate void LogAppendDelegate(Color color, string text);

        /// <summary> 
        /// 追加显示文本 
        /// </summary> 
        /// <param name="color">文本颜色</param> 
        /// <param name="text">显示文本</param> 
        public void LogAppend(Color color, string text)
        {
            if (this.txt_log.Text.Length > 10000)
            {
                this.txt_log.Clear();
            }
            this.txt_log.SelectionColor = color;
            this.txt_log.HideSelection = false;
            this.txt_log.AppendText(text + Environment.NewLine);
        }
        /// <summary> 
        /// 显示错误日志 
        /// </summary> 
        /// <param name="text"></param> 
        public void LogError(string text)
        {
            LogAppendDelegate la = new LogAppendDelegate(LogAppend);
            this.txt_log.Invoke(la, Color.Red, DateTime.Now + "----" + text);
        }
        /// <summary> 
        /// 显示警告信息 
        /// </summary> 
        /// <param name="text"></param> 
        public void LogWarning(string text)
        {
            LogAppendDelegate la = new LogAppendDelegate(LogAppend);
            this.txt_log.Invoke(la, Color.Violet, DateTime.Now + "----" + text);
        }
        /// <summary> 
        /// 显示一般信息 
        /// </summary> 
        /// <param name="text"></param> 
        public void LogMessage(string text)
        {
            LogAppendDelegate la = new LogAppendDelegate(LogAppend);
            this.txt_log.Invoke(la, Color.Black, DateTime.Now + "----" + text);
        }
        /// <summary> 
        /// 显示正确信息 
        /// </summary> 
        /// <param name="text"></param> 
        public void LogInfo(string text)
        {
            LogAppendDelegate la = new LogAppendDelegate(LogAppend);
            this.txt_log.Invoke(la, Color.Green, DateTime.Now + "----" + text);
        }


        private long lastCount = 0;
        private void updateStatus()
        {
            try
            {
                if (stp != null)
                {
                    long workCount = allCrackCount;

                    this.stxt_speed.Text = (workCount - this.lastCount) + "";
                    this.lastCount = workCount;
                    this.stxt_threadStatus.Text = stp.InUseThreads + "/" + stp.Concurrency;

                    int c = 0;
                    if (this.creackerSumCount != 0)
                    {
                        c = (int)Math.Floor((workCount * 100 / (double)this.creackerSumCount));
                        this.stxt_threadPoolStatus.Text = allCrackCount + "/" + this.creackerSumCount;
                    }
                    if (c <= 0)
                    {
                        c = 0;
                    }
                    if (c >= 100)
                    {
                        c = 100;
                    }
                    this.stxt_percent.Text = c + "%";
                    this.tools_proBar.Value = c;
                }
                this.stxt_crackerSuccessCount.Text = successCount + "";
                this.stxt_useTime.Text = runTime + "";
                this.tssl_notScanPortsSumCount.Text = this.scanPortsSumCount + "";
            }
            catch (Exception e)
            {
                LogWarning(e.Message);
            }
        }

        private void bt_timer_Tick(object sender, EventArgs e)
        {
            runTime++;
            this.Invoke(new update(updateStatus));

        }

        delegate void update();


        delegate void DelegateAddItem(ListViewItem lvi);

        private void addItem(ListViewItem lvi)
        {

            this.list_lvw.Items.Add(lvi);
        }

        public void ScanPort(string ip, string serviceName, int port)
        {

            //直接使用TcpClient类
            TcpClient tc = new TcpClient();
            //设置超时时间
            tc.SendTimeout = tc.ReceiveTimeout = 2000;

            try
            {
                //异步方法
                IAsyncResult oAsyncResult = tc.BeginConnect(ip, port, null, null);
                oAsyncResult.AsyncWaitHandle.WaitOne(2000, true);

                if (tc.Connected)
                {
                    lock (list_cracker)
                    {
                        list_cracker.Add(ip + ":" + port + ":" + serviceName);
                    }
                    tc.Close();
                    LogMessage(ip + " port " + port + " 开放！");
                    FileTool.AppendLogToFile(Directory.GetCurrentDirectory() + "/logs/portscan-" + DateTime.Now.ToString("yyyy-MM-dd") + ".log", ip + ":" + port + ":" + serviceName);
                }
                else
                {

                    //LogWarning(ip + " port " + port + " 连接超时！");
                }
            }
            catch (SocketException e)
            {

                LogWarning(ip + " port " + port + " 关闭！" + e.Message);
            }
            finally
            {
                tc.Close();

            }
            Interlocked.Decrement(ref scanPortsSumCount);
        }

        private void crackerService(string crakerstring, string username, string password)
        {
            try
            {
                string[] crakers = crakerstring.Split(':');
                string ip = crakers[0];
                int port = int.Parse(crakers[1]);
                string serviceName = crakers[2];

                //跳过无法检查的IP列表，提高效率
                //多线程安全
                lock (list_ip_break)
                {
                    if (list_ip_break.Contains(ip + port))
                    {
                        //LogWarning(ip+"-"+port+"跳过检查!");
                        Interlocked.Increment(ref allCrackCount);
                        return;
                    }
                }
                //多线程安全
                lock (list_ip_user_break)
                {
                    //跳过已经检查的列表，提高效率
                    if (list_ip_user_break.Contains(ip + port + username))
                    {
                        LogWarning(ip + "-" + port + "-" + username + "跳过检查!");
                        Interlocked.Increment(ref allCrackCount);
                        return;
                    }
                }


                if (true)
                {
                    Object[] pramars = { ip, port, username, password, timeOut, retryCount };

                    int count = 0;
                    Server server = new Server();

                    while (count <= this.retryCount)
                    {
                        count++;
                        try
                        { //跳过检查，多线程安全
                            bool cconce = false;
                            lock (list_success_username)
                            {
                                cconce = list_success_username.Contains(ip + serviceName + port);
                            }
                            if (this.crackerOneCount && cconce)
                            {
                                break;
                            }
                            Stopwatch sw = new Stopwatch();
                            sw.Start();

                            if (serviceName.Equals("RDP"))
                            {
                                server.ip = ip;
                                server.timeout = timeOut;
                                server.serverName = "RDP";
                                server.port = port;
                                server.username = username;
                                server.password = password;
                                server = creackRDP(server);
                            }
                            else
                            {
                                CrackService cs = null;
                                if (cs == null)
                                {
                                    Type type = Type.GetType("SNETCracker.Model.Crack" + serviceName);
                                    if (type != null)
                                    {
                                        cs = (CrackService)Activator.CreateInstance(type);

                                    }
                                }
                                server = cs.creack(ip, port, username, password, timeOut);

                            }
                            sw.Stop();
                            server.userTime = sw.ElapsedMilliseconds;

                        }
                        catch (IPBreakException ie)
                        {
                            string breakip = ie.Message;
                            lock (list_ip_break)
                            {
                                if (!list_ip_break.Contains(breakip))
                                {
                                    list_ip_break.Add(breakip);
                                }
                            }
                        }
                        catch (IPUserBreakException ie)
                        {
                            lock (list_ip_break)
                            {
                                string breakipuser = ie.Message;
                                if (!list_ip_break.Contains(breakipuser))
                                {
                                    list_ip_user_break.Add(breakipuser);
                                }
                            }
                        }
                        catch (TimeoutException te)
                        {
                            continue;
                        }
                        catch (Exception e)
                        {
                            string logInfo = "检查" + ip + ":" + serviceName + "登录发生异常！" + e.Message;
                            LogWarning(logInfo);
                            FileTool.log(logInfo + e.StackTrace);
                        }
                        break;
                    }
                    if (server.isSuccess)
                    {
                        bool success = false;
                        lock (list_success_username)
                        {
                            success = list_success_username.Contains(ip + serviceName + port + username);
                        }
                        if (!success)
                        {
                            if (this.crackerOneCount)
                            {
                                //多线程安全
                                lock (list_success_username)
                                {
                                    success = list_success_username.Contains(ip + serviceName + port);
                                }
                            }
                            if (!success)
                            {
                                //多线程安全
                                lock (list_success_username)
                                {
                                    list_success_username.Add(ip + serviceName + port);
                                    list_success_username.Add(ip + serviceName + port + username);
                                }
                                Interlocked.Increment(ref successCount);
                                addItemToListView(successCount, ip, serviceName, port, username, password, server.banner, server.userTime);
                                String sinfo = ip + "-----" + serviceName + "----" + username + "----" + password + "----" + server.banner + "----成功！";
                                LogInfo(sinfo);
                                FileTool.AppendLogToFile(Directory.GetCurrentDirectory() + "/logs/success-" + DateTime.Now.ToString("yyyy-MM-dd") + ".log", sinfo);

                            }

                        }

                    }
                    else
                    {
                        //LogWarning(ip + "-----" + serviceName + "----" + username + "----" + password + "失败！");
                    }

                }

            }
            catch (Exception e)
            {
                LogError(e.Message + e.StackTrace);
            }
            Interlocked.Increment(ref allCrackCount);
        }

        private void addItemToListView(int successCount, string ip, String serviceName, int port, String username, String password, String banner, long userTime)
        {

            ListViewItem lvi = new ListViewItem(successCount.ToString());
            lvi.SubItems.Add(ip);
            lvi.SubItems.Add(serviceName);
            lvi.SubItems.Add(port.ToString());
            lvi.SubItems.Add(username);
            lvi.SubItems.Add(password);
            lvi.SubItems.Add(banner);
            lvi.SubItems.Add(userTime + "");
            this.list_lvw.Invoke(new DelegateAddItem(addItem), lvi);
        }

        delegate void VoidDelegate();
        private SmartThreadPool stp = null;
        private void cracker()
        {
            crakerKey();
            this.Invoke(new VoidDelegate(this.bt_timer.Start));
            this.runTime = 0;
            if (initDic())
            {
                //初始化检查次数
                initStatusCount();
                //清空检查列表
                this.list_cracker = new ConcurrentBag<string>();
                //清空跳过列表
                this.list_ip_break.Clear();
                this.list_ip_user_break.Clear();
                Boolean isScanport = this.chk_isScanPort.Checked;
                stp = new SmartThreadPool();
                stp.MaxThreads = maxThread;
                creackerSumCount = 0;
                scanPortsSumCount = 0;


                //计算端口扫描总数
                if (isScanport)
                {
                    foreach (string serviceName in this.services_list.CheckedItems)
                    {
                        string[] ports = this.services[serviceName].Port.Split(',');
                        scanPortsSumCount += this.list_target.Count * ports.Length;
                    }
                }
                //更新状态
                this.Invoke(new update(updateStatus));

                foreach (string serviceName in this.services_list.CheckedItems)
                {
                    string[] ports = this.services[serviceName].Port.Split(',');
                    foreach (string sport in ports)
                    {
                        int port = int.Parse(sport);

                        foreach (string ip in list_target)
                        {
                            if (!isScanport)
                            {
                                list_cracker.Add(ip + ":" + port + ":" + serviceName);
                            }
                            else
                            {
                                stp.QueueWorkItem<string, string, int>(ScanPort, ip, serviceName, port);
                                stp.WaitFor(maxThread);
                            }
                        }
                    }

                }

                stp.WaitForIdle();
                if (isScanport)
                {
                    LogMessage("验证端口是否开放完成!");
                }
                int c = stp.CurrentWorkItemsCount;
                LogMessage("开始检查" + this.list_cracker.Count + "个目标," + services_list.CheckedItems.Count + "个服务.......");
                //计算检查总数
                if (this.notAutoSelectDic == false)
                {
                    foreach (string serviceName in this.services_list.CheckedItems)
                    {
                        creackerSumCount += list_cracker.Count * this.services[serviceName].ListUserName.Count * this.services[serviceName].ListPassword.Count;
                    }
                }
                else
                {
                    creackerSumCount += list_cracker.Count * this.list_username.Count * this.list_password.Count * this.services_list.CheckedItems.Count;
                }

                foreach (string serviceName in this.services_list.CheckedItems)
                {
                    HashSet<string> clist_username = null;
                    HashSet<string> clist_password = null;
                    if (this.notAutoSelectDic == false)
                    {
                        clist_username = this.services[serviceName].ListUserName;
                        clist_password = this.services[serviceName].ListPassword;
                    }
                    else
                    {
                        clist_username = this.list_username;
                        clist_password = this.list_password;
                    }

                    foreach (string user in clist_username)
                    {
                        //替换变量密码
                        string username = user + this.txt_username_ext.Text;
                        HashSet<string> list_current_password = new HashSet<string>();

                        //redis不需要破解账户
                        if (serviceName.Equals("Redis"))
                        {
                            username = "/";
                        }

                        foreach (string cpass in clist_password)
                        {
                            string newpass = cpass.Replace("%user%", user);
                            if (!list_current_password.Contains(newpass))
                            {
                                list_current_password.Add(newpass);

                            }
                            else
                            {
                                //重复密码
                                creackerSumCount -= this.list_cracker.Count * clist_username.Count;
                            }

                        }
                        foreach (string pass in list_current_password)
                        {
                            foreach (string cracker in this.list_cracker)
                            {
                                if (cracker.EndsWith(serviceName))
                                {
                                    stp.QueueWorkItem<string, string, string>(crackerService, cracker, username, pass);
                                    stp.WaitFor(maxThread);
                                }
                            }
                        }
                        //redis不需要破解账户
                        if (serviceName.Equals("Redis"))
                        {
                            break;
                        }
                    }
                }
                stp.WaitForIdle();
                stp.Shutdown();
                LogInfo("检查完成！");

            }
            //更新状态
            this.Invoke(new update(updateStatus));
            this.btn_cracker.Enabled = true;
            this.services_list.Enabled = true;
            this.Invoke(new VoidDelegate(this.bt_timer.Stop));
        }

        public void stopCraker()
        {
            if (stp != null && !stp.IsShuttingdown && this.crackerThread != null)
            {
                LogWarning("等待线程结束...");
                stp.Cancel();
                this.crackerThread.Abort();
                while (stp.InUseThreads > 0)
                {
                    Thread.Sleep(50);
                }

                //更新状态
                this.Invoke(new update(updateStatus));
                this.btn_cracker.Enabled = true;
                this.services_list.Enabled = true;
                this.bt_timer.Stop();
                LogWarning("全部线程已停止！");
            }
        }
        private Boolean initDic()
        {

            if ("".Equals(this.txt_target.Text))
            {
                MessageBox.Show("请设置需要检查的目标的IP地址或域名！");
                return false;
            }
            else if (this.services_list.CheckedItems.Count <= 0)
            {
                MessageBox.Show("请选择需要检查服务！");
                return false;
            }
            else
            {
                if (!"".Equals(this.txt_target.Text))
                {

                    bool isTrue = Regex.IsMatch(this.txt_target.Text, "^([\\w\\-\\.]{1,100}[a-zA-Z]{1,8})$|^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})$");
                    if (isTrue)
                    {
                        this.list_target.Clear();
                        this.list_target.Add(this.txt_target.Text);
                    }
                    else
                    {
                        isTrue = Regex.IsMatch(this.txt_target.Text, "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\-\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

                        if (isTrue)
                        {
                            this.list_target.Clear();
                            string[] ips = this.txt_target.Text.Split('-');
                            if (ips.Length == 2)
                            {
                                string startip = ips[0];
                                string endip = ips[1];
                                string[] startips = startip.Split('.');
                                string[] endips = endip.Split('.');
                                if (startips.Length == 4 && endips.Length == 4)
                                {
                                    int startips_3 = int.Parse(startips[2]);
                                    int endips_3 = int.Parse(endips[2]);
                                    int startips_4 = int.Parse(startips[3]);
                                    int endips_4 = int.Parse(endips[3]);

                                    if (endips_3 >= startips_3 && endips_3 <= 255 && endips_4 <= 255)
                                    {

                                        for (int i = startips_3; i <= endips_3; i++)
                                        {

                                            if (startips_3 == endips_3)
                                            {
                                                if (startips_4 <= endips_4)
                                                {
                                                    for (int j = startips_4; j <= endips_4; j++)
                                                    {
                                                        string ip = startips[0] + "." + startips[1] + "." + startips[2] + "." + j;
                                                        this.list_target.Add(ip);
                                                    }
                                                }

                                            }
                                            else
                                            {
                                                int index_start = 0;
                                                int index_end = 255;
                                                if (i == startips_3)
                                                {
                                                    index_start = startips_4;
                                                }
                                                if (i == endips_3)
                                                {
                                                    index_end = endips_4;
                                                }

                                                for (int j = index_start; j <= index_end; j++)
                                                {
                                                    string ip = startips[0] + "." + startips[1] + "." + i + "." + j;
                                                    this.list_target.Add(ip);
                                                }

                                            }
                                        }

                                    }
                                }

                            }


                        }
                        else
                        {
                            this.list_target = this.list_import_target;
                        }
                    }
                    if (this.list_target.Count <= 0)
                    {
                        MessageBox.Show("目标格式错误！\r\n格式示例：\r\n192.168.1.1\r\nwww.baidu.com\r\n192.168.1.1-192.168.200.1\r\n192.168.1.1-192.168.1.200");
                        return false;
                    }
                }

            }
            //加载自定义字典字典
            if (notAutoSelectDic)
            {
                if (this.txt_username.Text.EndsWith(".txt"))
                {
                    this.list_username = FileTool.readFileToList(this.txt_username.Text);
                }
                else
                {
                    if (this.txt_username.Text.Length > 0)
                    {
                        this.list_username.Clear();
                        this.list_username.Add(this.txt_username.Text);
                    }
                }

                if (this.txt_password.Text.EndsWith(".txt"))
                {
                    this.list_password = FileTool.readFileToList(this.txt_password.Text);
                }
                else
                {
                    if (this.txt_password.Text.Length > 0)
                    {
                        this.list_password.Clear();
                        this.list_password.Add(this.txt_password.Text);
                    }
                }

                if (this.list_username.Count <= 0)
                {
                    MessageBox.Show("请设置需要检查的用户名！");
                    return false;
                }
                else if (this.list_password.Count <= 0)
                {
                    MessageBox.Show("请设置检查的密码！");
                    return false;
                }
            }
            else
            {
                //如果默认字典没有数据则加载默认字典

                if (dics.Count <= 0)
                {
                    LogMessage("根据选择检查的服务自动加载字典......");

                    foreach (string serviceName in this.services_list.CheckedItems)
                    {
                        ServiceModel sm = this.services[serviceName];
                        sm.ListUserName = FileTool.readFileToList(Directory.GetCurrentDirectory() + sm.DicUserNamePath);
                        sm.ListPassword = FileTool.readFileToList(Directory.GetCurrentDirectory() + sm.DicPasswordPath);
                        if (sm.ListUserName.Count <= 0)
                        {
                            LogWarning("加载" + serviceName + "用户名字典未发现数据！");
                        }
                        else if (sm.ListPassword.Count <= 0)
                        {
                            LogWarning("加载" + serviceName + "密码字典未发现数据！");
                        }
                        else
                        {
                            LogWarning("加载" + serviceName + "字典成功，用户名" + sm.ListUserName.Count + "个，密码" + sm.ListPassword.Count + "个！");
                        }
                    }
                    LogMessage("根据选择检查的服务自动加载字典完成！");
                }
            }
            return true;

        }

        private void crakerKey()
        {
            var forBuild = 65535;
            var validTillDate = DateTime.Now.AddDays(64).Subtract(new DateTime(2010, 12, 31)).TotalDays;

            var forgedBytes = new byte[16];
            forgedBytes[0] = (byte)(validTillDate / 256);
            forgedBytes[1] = (byte)(validTillDate % 256);
            forgedBytes[2] = (byte)(forBuild / 256);
            forgedBytes[3] = (byte)(forBuild % 256);

            var output = new byte[32];
            output[0] = 7;
            var rnd = new Random();
            for (var x = 1; x < 13; x++)
                output[x] = (byte)rnd.Next(1, 256);

            Array.Copy(forgedBytes, 0, output, 14, forgedBytes.Length);

            var rsaManaged2 = new RSAManaged();
            rsaManaged2.FromXmlString("<RSAKeyValue><Modulus>thycVKzZzdxBD6Rl8RoS9MEs1rrLY5qDhse+a+ljfpM=</Modulus><Exponent>AQAB</Exponent><P>xJXNbvuhJEpA647ZChJHMQ==</P><Q>7Sb4m1/8WXGGL/2Zw075Aw==</Q><DP>VtattvbkyfkbEHM7oN1OIQ==</DP><DQ>0kQaatCpErjYDBbjTUro9w==</DQ><InieQ>AVeR8pKZ4H05p7NRb02kNw==</InverseQ><D>ENshFS1Sk51ZYEtFLEXPjzPUmZbbIak0S+dyUK5o/sE=</D></RSAKeyValue>");

            var decrypted = rsaManaged2.DecryptValue(output);

            var key = "==A" + Convert.ToBase64String(decrypted) + "=";
            string a = key.ToString();
            Rebex.Licensing.Key = a;
        }
        Thread crackerThread = null;
        public void rdpResult(ResponseType type, RdpClient rdp, ref Server server)
        {

            //接受事件通知，表示完成后，将当前阻塞线程放过继续执行。
            if (ResponseType.Finished.Equals(type))
            {
                server.isDisConnected = true;
                server.isEndMRE.Set();
            }

        }

        delegate Server addRDPdelegate(Server server);
        private Server addRDPClient(Server server)
        {

            try
            {
                RdpClient rdp = new RdpClient();
                server.client = rdp;
                server.client.server = server;

                this.rdp_panle.Controls.Add(rdp);
                server.client.OnResponse += rdpResult;
                server.client.ConnectServer(server);

            }
            catch (Exception e)
            {
                FileTool.log(server.ip + ":" + server.port + "-RDP操作异常-" + e.Message);
                LogWarning(server.ip + ":" + server.port + "-RDP操作异常-" + e.Message);
                server.isDisConnected = true;
                server.isEndMRE.Set();
            }
            return server;

        }

        private delegate void deleteClearRDP(Server server);
        private void ClearRDP(Server server)
        {
            try
            {
                RdpClient rdp = server.client;
                if (rdp.Connected != 0)
                {
                    rdp.RequestClose();
                    rdp.Disconnect();
                }
                rdp.Dispose();
                this.rdp_panle.Controls.Remove(rdp);
            }
            catch (Exception e)
            {
                FileTool.log("RDP资源清理异常-" + e.Message);
                LogWarning("RDP资源清理异常-" + e.Message);
            }
        }

        private Server creackRDP(Server server)
        {
            try
            {

                this.rdp_panle.Invoke(new addRDPdelegate(addRDPClient), server);
                server.isEndMRE.WaitOne(server.timeout * 1000, true);
                this.rdp_panle.Invoke(new deleteClearRDP(ClearRDP), server);

            }
            catch (Exception e)
            {
                FileTool.log("创建RDP控件发生错误：" + e.Message);
            }
            return server;
        }




        private void btn_cracker_Click(object sender, EventArgs e)
        {
            this.btn_cracker.Enabled = false;
            this.list_success_username.Clear();
            this.services_list.Enabled = false;

            crackerThread = new Thread(cracker);
            crackerThread.Start();

        }

        private void initStatusCount()
        {
            successCount = 0;
            allCrackCount = 0;
        }


        private void Main_Shown(object sender, EventArgs e)
        {
            this.Text += " " + Main.version + "";

            this.cbox_reTry.SelectedIndex = 0;
            this.cbox_threadSize.SelectedIndex = 10;
            this.cbox_timeOut.SelectedIndex = 2;

            //加载默认配置
            initServices();

            foreach (string key in services.Keys)
            {
                this.services_list.Items.Add(key);
            }
            Thread th = new Thread(checkUpdate);
            th.Start();
        }

        private void btn_importUername_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog { Filter = "文本文件(*.txt)|*.txt" };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                if (!string.IsNullOrEmpty(ofd.FileName))
                {
                    this.txt_username.Text = ofd.FileName;
                    LogInfo("导入用户名成功！");
                }
            }
        }

        private void btn_importPassword_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog { Filter = "文本文件(*.txt)|*.txt" };
            if (ofd.ShowDialog() == DialogResult.OK)
            {

                if (!string.IsNullOrEmpty(ofd.FileName))
                {
                    this.txt_password.Text = ofd.FileName;
                    LogInfo("导入密码字典成功！");
                }
            }
        }

        private void updateThreadSize()
        {

            this.maxThread = int.Parse(this.cbox_threadSize.Text);
            if (stp != null)
            {
                stp.MaxThreads = this.maxThread;
            }
        }

        private void cbox_timeOut_TextChanged(object sender, EventArgs e)
        {
            this.timeOut = int.Parse(this.cbox_timeOut.Text);
        }

        private void cbox_reTry_TextChanged(object sender, EventArgs e)
        {
            this.retryCount = int.Parse(this.cbox_reTry.Text);
        }
        private void btn_stopCracker_Click(object sender, EventArgs e)
        {
            Thread th = new Thread(stopCraker);
            th.Start();
        }

        private void Main_FormClosing(object sender, FormClosingEventArgs e)
        {
            Application.Exit();
        }

        private void chk_notAutoSelectDic_CheckedChanged(object sender, EventArgs e)
        {
            this.notAutoSelectDic = this.chk_notAutoSelectDic.Checked;
            this.txt_username.Enabled = this.notAutoSelectDic;
            this.txt_password.Enabled = this.notAutoSelectDic;
            this.btn_importUername.Enabled = this.notAutoSelectDic;
            this.btn_importPassword.Enabled = this.notAutoSelectDic;
        }

        private void chk_crackerOneCount_CheckedChanged(object sender, EventArgs e)
        {
            this.crackerOneCount = this.chk_crackerOneCount.Checked;
        }
        private void readListFile(Object path)
        {
            this.list_import_target = FileTool.readFileToList(path.ToString());
            LogInfo("读取检查列表完成,导入地址：" + this.list_import_target.Count + "条！");
            this.btn_cracker.Enabled = true;
        }
        private void btn_importList_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog { Filter = "文本文件(*.txt)|*.txt" };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                string filePath = ofd.FileName;
                this.txt_target.Text = filePath;
                this.btn_cracker.Enabled = false;
                Thread th = new Thread(readListFile);
                th.Start(ofd.FileName);
                LogInfo("正在读取检查列表！");

            }
        }
        private void exportResult()
        {

            //保存文件
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "文本文件|*.csv";
            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    FileStream fs = new FileStream(saveFileDialog.FileName, FileMode.OpenOrCreate, System.IO.FileAccess.Write);
                    StreamWriter sw = new StreamWriter(fs);
                    string columns = "";
                    foreach (ColumnHeader dc in this.list_lvw.Columns)
                    {
                        columns += ("\"" + dc.Text + "\",");
                    }
                    sw.WriteLine(columns.Substring(0, columns.Length - 1));
                    foreach (ListViewItem sv in this.list_lvw.Items)
                    {
                        System.Text.StringBuilder sb = new System.Text.StringBuilder();
                        foreach (ListViewItem.ListViewSubItem subv in sv.SubItems)
                        {
                            sb.Append("\"" + subv.Text + "\",");
                        }
                        sb.Remove(sb.Length - 1, 1);
                        sw.WriteLine(sb.ToString());
                    }
                    sw.Close();
                    MessageBox.Show("导出完成！");
                }
                catch (Exception e)
                {
                    FileTool.log("导出数据发生异常！" + e.Message);
                    MessageBox.Show("导出数据发生异常！");
                }
            }
        }
        private void tsmi_options_export_Click(object sender, EventArgs e)
        {
            exportResult();
        }

        private void tsmi_export_Click(object sender, EventArgs e)
        {
            exportResult();
        }

        private void tsmi_deleteSelectItem_Click(object sender, EventArgs e)
        {
            if (this.list_lvw.SelectedItems.Count == 0)
            {
                return;
            }
            foreach (ListViewItem selitem in this.list_lvw.SelectedItems)
            {
                this.list_lvw.Items.Remove(selitem);
            }
        }

        private void tsmi_copyItem_Click(object sender, EventArgs e)
        {
            if (this.list_lvw.SelectedItems.Count == 0)
            {
                return;
            }
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 1; i <= 5; i++)
            {
                sb.Append("----");
                sb.Append(this.list_lvw.SelectedItems[0].SubItems[i].Text);
            }
            Clipboard.SetText(sb.Remove(0, 4).ToString());
            MessageBox.Show("复制成功！");
        }
        private void tsmi_clearItems_Click(object sender, EventArgs e)
        {
            this.list_lvw.Items.Clear();
        }

        private void tsmi_openURL_Click(object sender, EventArgs e)
        {
            if (this.list_lvw.SelectedItems.Count == 0)
            {
                return;
            }
            string target = "http://" + this.list_lvw.SelectedItems[0].SubItems[1].Text + ":" + this.list_lvw.SelectedItems[0].SubItems[1].Text;

            try
            {
                System.Diagnostics.Process.Start("IEXPLORE.EXE", target);
            }
            catch (Exception oe)
            {
                MessageBox.Show("打开URL发生异常---" + oe.Message);
            }
        }

       

        private static int version = 20190715;
        public static string versionURL = "http://www.shack2.org/soft/getNewVersion?ENNAME=SNETCracker&NO=" + Uri.EscapeDataString(Tool.getSystemSid()) + "&VERSION=" + version;
        private void tsmi_help_version_Click(object sender, EventArgs e)
        {
            MessageBox.Show("V1.0 测试版----" + version);
        }
        public void checkUpdate()
        {
            try
            {
                string[] result = Tool.getHtml(versionURL, 30).Split('-');
                string versionText = result[0];
                int cversion = int.Parse(result[1]);
                string versionUpdateURL = result[2];
                if (cversion > version)
                {
                    DialogResult dr = MessageBox.Show("发现新版本：" + versionText + "，更新日期：" + cversion + "，立即更新吗？", "提示", MessageBoxButtons.OKCancel);

                    if (DialogResult.OK.Equals(dr))
                    {
                        try
                        {
                            int index = versionUpdateURL.LastIndexOf("/");
                            string filename = "/update.rar";
                            if (index != -1)
                            {
                                filename = versionUpdateURL.Substring(index);
                            }
                            Tool.HttpDownloadFile(versionUpdateURL, Directory.GetCurrentDirectory() + filename);
                            MessageBox.Show("更新成功，请将解压后运行！");
                        }
                        catch (Exception other)
                        {
                            MessageBox.Show("更新失败，请访问官网更新！" + other.GetBaseException());
                        }
                    }
                }
                else
                {
                    LogMessage("自动检查更新，没有发现新版本！");
                }
            }
            catch (Exception e)
            {
                LogMessage("检查更新，联网失败！" + e.Message);
            }
        }

        private void tsmi_help_support_Click(object sender, EventArgs e)
        {
            MessageBox.Show("请将建议或程序BUG发送邮件到1341413415@qq.com，谢谢!");
        }

        private void tsmi_options_import_Click(object sender, EventArgs e)
        {

        }

        private void tsmi_help_about_Click(object sender, EventArgs e)
        {
            MessageBox.Show("此工具为常见服务弱口令检查工具，提供给企业、运维人员、安全工程师进行企业内部弱口令检查使用，请勿非法使用！");
        }

        private void tsmi_help_update_Click(object sender, EventArgs e)
        {
            checkUpdate();
        }
        private void tsmi_set_Click(object sender, EventArgs e)
        {
            Seting set = new Seting();
            set.ShowDialog();
        }

        private void cbox_threadSize_SelectedIndexChanged(object sender, EventArgs e)
        {
            updateThreadSize();
        }

        private void tsmi_reloadConfig_Click(object sender, EventArgs e)
        {
            initServices();
            MessageBox.Show("ok");

        }


    }
}
