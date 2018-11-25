namespace SNETCracker
{
    partial class Main
    {
        /// <summary>
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.services_list = new System.Windows.Forms.CheckedListBox();
            this.chk_crackerOneCount = new System.Windows.Forms.CheckBox();
            this.chk_notAutoSelectDic = new System.Windows.Forms.CheckBox();
            this.chk_isScanPort = new System.Windows.Forms.CheckBox();
            this.cbox_reTry = new System.Windows.Forms.ComboBox();
            this.cbox_timeOut = new System.Windows.Forms.ComboBox();
            this.cbox_threadSize = new System.Windows.Forms.ComboBox();
            this.btn_stopCracker = new System.Windows.Forms.Button();
            this.btn_cracker = new System.Windows.Forms.Button();
            this.btn_importPassword = new System.Windows.Forms.Button();
            this.btn_importUername = new System.Windows.Forms.Button();
            this.btn_importList = new System.Windows.Forms.Button();
            this.txt_username_ext = new System.Windows.Forms.TextBox();
            this.txt_password = new System.Windows.Forms.TextBox();
            this.txt_username = new System.Windows.Forms.TextBox();
            this.txt_target = new System.Windows.Forms.TextBox();
            this.label8 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.txt_log = new System.Windows.Forms.RichTextBox();
            this.list_lvw = new System.Windows.Forms.ListView();
            this.col_id = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.col_ip = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.col_serviceName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.col_port = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.col_username = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.col_pass = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.col_banner = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.col_useTime = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.cms_lvw = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.tsmi_export = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_deleteSelectItem = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_clearItems = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_openURL = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_copyItem = new System.Windows.Forms.ToolStripMenuItem();
            this.rdp_panle = new System.Windows.Forms.Panel();
            this.bt_status = new System.Windows.Forms.StatusStrip();
            this.toolStripStatusLabel1 = new System.Windows.Forms.ToolStripStatusLabel();
            this.tools_proBar = new System.Windows.Forms.ToolStripProgressBar();
            this.stxt_percent = new System.Windows.Forms.ToolStripStatusLabel();
            this.toolStripStatusLabel2 = new System.Windows.Forms.ToolStripStatusLabel();
            this.stxt_useTime = new System.Windows.Forms.ToolStripStatusLabel();
            this.s_txt_threadlable = new System.Windows.Forms.ToolStripStatusLabel();
            this.stxt_threadStatus = new System.Windows.Forms.ToolStripStatusLabel();
            this.toolStripStatusLabel6 = new System.Windows.Forms.ToolStripStatusLabel();
            this.stxt_threadPoolStatus = new System.Windows.Forms.ToolStripStatusLabel();
            this.toolStripStatusLabel3 = new System.Windows.Forms.ToolStripStatusLabel();
            this.stxt_crackerSuccessCount = new System.Windows.Forms.ToolStripStatusLabel();
            this.toolStripStatusLabel5 = new System.Windows.Forms.ToolStripStatusLabel();
            this.stxt_speed = new System.Windows.Forms.ToolStripStatusLabel();
            this.bt_timer = new System.Windows.Forms.Timer(this.components);
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.tsmi_options = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_options_export = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_options_import = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_reloadConfig = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_set = new System.Windows.Forms.ToolStripMenuItem();
            this.帮助ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_help_about = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_help_update = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_help_version = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_help_support = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_tools = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripStatusLabel4 = new System.Windows.Forms.ToolStripStatusLabel();
            this.tssl_notScanPortsSumCount = new System.Windows.Forms.ToolStripStatusLabel();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.cms_lvw.SuspendLayout();
            this.bt_status.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.services_list);
            this.groupBox1.Controls.Add(this.chk_crackerOneCount);
            this.groupBox1.Controls.Add(this.chk_notAutoSelectDic);
            this.groupBox1.Controls.Add(this.chk_isScanPort);
            this.groupBox1.Controls.Add(this.cbox_reTry);
            this.groupBox1.Controls.Add(this.cbox_timeOut);
            this.groupBox1.Controls.Add(this.cbox_threadSize);
            this.groupBox1.Controls.Add(this.btn_stopCracker);
            this.groupBox1.Controls.Add(this.btn_cracker);
            this.groupBox1.Controls.Add(this.btn_importPassword);
            this.groupBox1.Controls.Add(this.btn_importUername);
            this.groupBox1.Controls.Add(this.btn_importList);
            this.groupBox1.Controls.Add(this.txt_username_ext);
            this.groupBox1.Controls.Add(this.txt_password);
            this.groupBox1.Controls.Add(this.txt_username);
            this.groupBox1.Controls.Add(this.txt_target);
            this.groupBox1.Controls.Add(this.label8);
            this.groupBox1.Controls.Add(this.label5);
            this.groupBox1.Controls.Add(this.label4);
            this.groupBox1.Controls.Add(this.label3);
            this.groupBox1.Controls.Add(this.label2);
            this.groupBox1.Controls.Add(this.label7);
            this.groupBox1.Controls.Add(this.label6);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Dock = System.Windows.Forms.DockStyle.Top;
            this.groupBox1.Location = new System.Drawing.Point(0, 25);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(876, 138);
            this.groupBox1.TabIndex = 0;
            this.groupBox1.TabStop = false;
            // 
            // services_list
            // 
            this.services_list.FormattingEnabled = true;
            this.services_list.Location = new System.Drawing.Point(41, 14);
            this.services_list.Name = "services_list";
            this.services_list.Size = new System.Drawing.Size(107, 116);
            this.services_list.TabIndex = 1;
            // 
            // chk_crackerOneCount
            // 
            this.chk_crackerOneCount.AutoSize = true;
            this.chk_crackerOneCount.Checked = true;
            this.chk_crackerOneCount.CheckState = System.Windows.Forms.CheckState.Checked;
            this.chk_crackerOneCount.Location = new System.Drawing.Point(750, 19);
            this.chk_crackerOneCount.Name = "chk_crackerOneCount";
            this.chk_crackerOneCount.Size = new System.Drawing.Size(108, 16);
            this.chk_crackerOneCount.TabIndex = 5;
            this.chk_crackerOneCount.Text = "只破解一个账户";
            this.chk_crackerOneCount.UseVisualStyleBackColor = true;
            this.chk_crackerOneCount.CheckedChanged += new System.EventHandler(this.chk_crackerOneCount_CheckedChanged);
            // 
            // chk_notAutoSelectDic
            // 
            this.chk_notAutoSelectDic.AutoSize = true;
            this.chk_notAutoSelectDic.Checked = true;
            this.chk_notAutoSelectDic.CheckState = System.Windows.Forms.CheckState.Checked;
            this.chk_notAutoSelectDic.Location = new System.Drawing.Point(433, 102);
            this.chk_notAutoSelectDic.Name = "chk_notAutoSelectDic";
            this.chk_notAutoSelectDic.Size = new System.Drawing.Size(156, 16);
            this.chk_notAutoSelectDic.TabIndex = 10;
            this.chk_notAutoSelectDic.Text = "不根据服务自动选择字典";
            this.chk_notAutoSelectDic.UseVisualStyleBackColor = true;
            this.chk_notAutoSelectDic.CheckedChanged += new System.EventHandler(this.chk_notAutoSelectDic_CheckedChanged);
            // 
            // chk_isScanPort
            // 
            this.chk_isScanPort.AutoSize = true;
            this.chk_isScanPort.Checked = true;
            this.chk_isScanPort.CheckState = System.Windows.Forms.CheckState.Checked;
            this.chk_isScanPort.Location = new System.Drawing.Point(517, 22);
            this.chk_isScanPort.Name = "chk_isScanPort";
            this.chk_isScanPort.Size = new System.Drawing.Size(72, 16);
            this.chk_isScanPort.TabIndex = 3;
            this.chk_isScanPort.Text = "扫描端口";
            this.chk_isScanPort.UseVisualStyleBackColor = true;
            // 
            // cbox_reTry
            // 
            this.cbox_reTry.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbox_reTry.FormattingEnabled = true;
            this.cbox_reTry.Items.AddRange(new object[] {
            "0",
            "1",
            "2"});
            this.cbox_reTry.Location = new System.Drawing.Point(663, 100);
            this.cbox_reTry.Name = "cbox_reTry";
            this.cbox_reTry.Size = new System.Drawing.Size(61, 20);
            this.cbox_reTry.TabIndex = 11;
            this.cbox_reTry.TextChanged += new System.EventHandler(this.cbox_reTry_TextChanged);
            // 
            // cbox_timeOut
            // 
            this.cbox_timeOut.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbox_timeOut.FormattingEnabled = true;
            this.cbox_timeOut.Items.AddRange(new object[] {
            "5",
            "10",
            "15",
            "20",
            "30",
            "40",
            "50",
            "60"});
            this.cbox_timeOut.Location = new System.Drawing.Point(663, 19);
            this.cbox_timeOut.Name = "cbox_timeOut";
            this.cbox_timeOut.Size = new System.Drawing.Size(61, 20);
            this.cbox_timeOut.TabIndex = 4;
            this.cbox_timeOut.TextChanged += new System.EventHandler(this.cbox_timeOut_TextChanged);
            // 
            // cbox_threadSize
            // 
            this.cbox_threadSize.AutoCompleteCustomSource.AddRange(new string[] {
            "导入信息自动选择"});
            this.cbox_threadSize.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbox_threadSize.FormattingEnabled = true;
            this.cbox_threadSize.Items.AddRange(new object[] {
            "1",
            "2",
            "3",
            "4",
            "5",
            "10",
            "15",
            "20",
            "30",
            "40",
            "50",
            "60",
            "70",
            "80",
            "90",
            "100",
            "150",
            "200",
            "250",
            "300",
            "400",
            "500",
            "600",
            "700",
            "800",
            "1000"});
            this.cbox_threadSize.Location = new System.Drawing.Point(663, 58);
            this.cbox_threadSize.Name = "cbox_threadSize";
            this.cbox_threadSize.Size = new System.Drawing.Size(61, 20);
            this.cbox_threadSize.TabIndex = 9;
            this.cbox_threadSize.SelectedIndexChanged += new System.EventHandler(this.cbox_threadSize_SelectedIndexChanged);
            // 
            // btn_stopCracker
            // 
            this.btn_stopCracker.Location = new System.Drawing.Point(750, 97);
            this.btn_stopCracker.Name = "btn_stopCracker";
            this.btn_stopCracker.Size = new System.Drawing.Size(108, 23);
            this.btn_stopCracker.TabIndex = 2;
            this.btn_stopCracker.Text = "停止检查";
            this.btn_stopCracker.UseVisualStyleBackColor = true;
            this.btn_stopCracker.Click += new System.EventHandler(this.btn_stopCracker_Click);
            // 
            // btn_cracker
            // 
            this.btn_cracker.Location = new System.Drawing.Point(750, 56);
            this.btn_cracker.Name = "btn_cracker";
            this.btn_cracker.Size = new System.Drawing.Size(108, 23);
            this.btn_cracker.TabIndex = 2;
            this.btn_cracker.Text = "开始检查";
            this.btn_cracker.UseVisualStyleBackColor = true;
            this.btn_cracker.Click += new System.EventHandler(this.btn_cracker_Click);
            // 
            // btn_importPassword
            // 
            this.btn_importPassword.Location = new System.Drawing.Point(348, 100);
            this.btn_importPassword.Name = "btn_importPassword";
            this.btn_importPassword.Size = new System.Drawing.Size(67, 23);
            this.btn_importPassword.TabIndex = 2;
            this.btn_importPassword.Text = "导 入";
            this.btn_importPassword.UseVisualStyleBackColor = true;
            this.btn_importPassword.Click += new System.EventHandler(this.btn_importPassword_Click);
            // 
            // btn_importUername
            // 
            this.btn_importUername.Location = new System.Drawing.Point(348, 58);
            this.btn_importUername.Name = "btn_importUername";
            this.btn_importUername.Size = new System.Drawing.Size(67, 23);
            this.btn_importUername.TabIndex = 2;
            this.btn_importUername.Text = "导 入";
            this.btn_importUername.UseVisualStyleBackColor = true;
            this.btn_importUername.Click += new System.EventHandler(this.btn_importUername_Click);
            // 
            // btn_importList
            // 
            this.btn_importList.Location = new System.Drawing.Point(433, 18);
            this.btn_importList.Name = "btn_importList";
            this.btn_importList.Size = new System.Drawing.Size(63, 23);
            this.btn_importList.TabIndex = 2;
            this.btn_importList.Text = "导入地址";
            this.btn_importList.UseVisualStyleBackColor = true;
            this.btn_importList.Click += new System.EventHandler(this.btn_importList_Click);
            // 
            // txt_username_ext
            // 
            this.txt_username_ext.Location = new System.Drawing.Point(502, 58);
            this.txt_username_ext.Name = "txt_username_ext";
            this.txt_username_ext.Size = new System.Drawing.Size(87, 21);
            this.txt_username_ext.TabIndex = 8;
            // 
            // txt_password
            // 
            this.txt_password.Location = new System.Drawing.Point(214, 101);
            this.txt_password.Name = "txt_password";
            this.txt_password.Size = new System.Drawing.Size(128, 21);
            this.txt_password.TabIndex = 7;
            // 
            // txt_username
            // 
            this.txt_username.Location = new System.Drawing.Point(213, 58);
            this.txt_username.Name = "txt_username";
            this.txt_username.Size = new System.Drawing.Size(129, 21);
            this.txt_username.TabIndex = 6;
            // 
            // txt_target
            // 
            this.txt_target.Location = new System.Drawing.Point(214, 20);
            this.txt_target.Name = "txt_target";
            this.txt_target.Size = new System.Drawing.Size(202, 21);
            this.txt_target.TabIndex = 2;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(610, 105);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(47, 12);
            this.label8.TabIndex = 0;
            this.label8.Text = "重 试：";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(431, 61);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(65, 12);
            this.label5.TabIndex = 0;
            this.label5.Text = "账户后缀：";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(610, 22);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(47, 12);
            this.label4.TabIndex = 0;
            this.label4.Text = "超 时：";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(610, 60);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(47, 12);
            this.label3.TabIndex = 0;
            this.label3.Text = "线 程：";
            // 
            // label2
            // 
            this.label2.Location = new System.Drawing.Point(14, 16);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(21, 100);
            this.label2.TabIndex = 0;
            this.label2.Text = "\r\n检 \r\n查 \r\n服\r\n 务";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(160, 106);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(47, 12);
            this.label7.TabIndex = 0;
            this.label7.Text = "密 码：";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(160, 61);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(47, 12);
            this.label6.TabIndex = 0;
            this.label6.Text = "账 户：";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(160, 23);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(47, 12);
            this.label1.TabIndex = 0;
            this.label1.Text = "目 标：";
            // 
            // groupBox2
            // 
            this.groupBox2.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox2.Controls.Add(this.txt_log);
            this.groupBox2.Controls.Add(this.list_lvw);
            this.groupBox2.Location = new System.Drawing.Point(0, 161);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(876, 491);
            this.groupBox2.TabIndex = 0;
            this.groupBox2.TabStop = false;
            // 
            // txt_log
            // 
            this.txt_log.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txt_log.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.txt_log.Location = new System.Drawing.Point(3, 415);
            this.txt_log.Name = "txt_log";
            this.txt_log.Size = new System.Drawing.Size(870, 76);
            this.txt_log.TabIndex = 1;
            this.txt_log.Text = "";
            // 
            // list_lvw
            // 
            this.list_lvw.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.list_lvw.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.col_id,
            this.col_ip,
            this.col_serviceName,
            this.col_port,
            this.col_username,
            this.col_pass,
            this.col_banner,
            this.col_useTime});
            this.list_lvw.ContextMenuStrip = this.cms_lvw;
            this.list_lvw.FullRowSelect = true;
            this.list_lvw.GridLines = true;
            this.list_lvw.Location = new System.Drawing.Point(3, 15);
            this.list_lvw.Name = "list_lvw";
            this.list_lvw.Size = new System.Drawing.Size(870, 394);
            this.list_lvw.TabIndex = 0;
            this.list_lvw.UseCompatibleStateImageBehavior = false;
            this.list_lvw.View = System.Windows.Forms.View.Details;
            // 
            // col_id
            // 
            this.col_id.Text = "序号";
            // 
            // col_ip
            // 
            this.col_ip.Text = "IP地址";
            this.col_ip.Width = 106;
            // 
            // col_serviceName
            // 
            this.col_serviceName.Text = "服 务";
            this.col_serviceName.Width = 84;
            // 
            // col_port
            // 
            this.col_port.Text = "端口";
            // 
            // col_username
            // 
            this.col_username.Text = "帐户名";
            this.col_username.Width = 83;
            // 
            // col_pass
            // 
            this.col_pass.Text = "密码";
            this.col_pass.Width = 100;
            // 
            // col_banner
            // 
            this.col_banner.Text = "BANNER";
            this.col_banner.Width = 100;
            // 
            // col_useTime
            // 
            this.col_useTime.Text = "用时[毫秒]";
            // 
            // cms_lvw
            // 
            this.cms_lvw.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.tsmi_export,
            this.tsmi_deleteSelectItem,
            this.tsmi_clearItems,
            this.tsmi_openURL,
            this.tsmi_copyItem});
            this.cms_lvw.Name = "cms_lvw";
            this.cms_lvw.Size = new System.Drawing.Size(137, 114);
            // 
            // tsmi_export
            // 
            this.tsmi_export.Name = "tsmi_export";
            this.tsmi_export.Size = new System.Drawing.Size(136, 22);
            this.tsmi_export.Text = "导出结果";
            this.tsmi_export.Click += new System.EventHandler(this.tsmi_export_Click);
            // 
            // tsmi_deleteSelectItem
            // 
            this.tsmi_deleteSelectItem.Name = "tsmi_deleteSelectItem";
            this.tsmi_deleteSelectItem.Size = new System.Drawing.Size(136, 22);
            this.tsmi_deleteSelectItem.Text = "删除选中行";
            this.tsmi_deleteSelectItem.Click += new System.EventHandler(this.tsmi_deleteSelectItem_Click);
            // 
            // tsmi_clearItems
            // 
            this.tsmi_clearItems.Name = "tsmi_clearItems";
            this.tsmi_clearItems.Size = new System.Drawing.Size(136, 22);
            this.tsmi_clearItems.Text = "清空结果";
            this.tsmi_clearItems.Click += new System.EventHandler(this.tsmi_clearItems_Click);
            // 
            // tsmi_openURL
            // 
            this.tsmi_openURL.Name = "tsmi_openURL";
            this.tsmi_openURL.Size = new System.Drawing.Size(136, 22);
            this.tsmi_openURL.Text = "打开URL";
            this.tsmi_openURL.Click += new System.EventHandler(this.tsmi_openURL_Click);
            // 
            // tsmi_copyItem
            // 
            this.tsmi_copyItem.Name = "tsmi_copyItem";
            this.tsmi_copyItem.Size = new System.Drawing.Size(136, 22);
            this.tsmi_copyItem.Text = "复 制";
            this.tsmi_copyItem.Click += new System.EventHandler(this.tsmi_copyItem_Click);
            // 
            // rdp_panle
            // 
            this.rdp_panle.BackgroundImageLayout = System.Windows.Forms.ImageLayout.None;
            this.rdp_panle.Location = new System.Drawing.Point(214, 9);
            this.rdp_panle.Name = "rdp_panle";
            this.rdp_panle.Size = new System.Drawing.Size(10, 10);
            this.rdp_panle.TabIndex = 12;
            // 
            // bt_status
            // 
            this.bt_status.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripStatusLabel1,
            this.tools_proBar,
            this.stxt_percent,
            this.toolStripStatusLabel2,
            this.stxt_useTime,
            this.s_txt_threadlable,
            this.stxt_threadStatus,
            this.toolStripStatusLabel6,
            this.stxt_threadPoolStatus,
            this.toolStripStatusLabel3,
            this.stxt_crackerSuccessCount,
            this.toolStripStatusLabel5,
            this.stxt_speed,
            this.toolStripStatusLabel4,
            this.tssl_notScanPortsSumCount});
            this.bt_status.Location = new System.Drawing.Point(0, 655);
            this.bt_status.Name = "bt_status";
            this.bt_status.Size = new System.Drawing.Size(876, 22);
            this.bt_status.TabIndex = 1;
            this.bt_status.Text = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            this.toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            this.toolStripStatusLabel1.Size = new System.Drawing.Size(48, 17);
            this.toolStripStatusLabel1.Text = "进 度：";
            // 
            // tools_proBar
            // 
            this.tools_proBar.Name = "tools_proBar";
            this.tools_proBar.Size = new System.Drawing.Size(200, 16);
            // 
            // stxt_percent
            // 
            this.stxt_percent.Name = "stxt_percent";
            this.stxt_percent.Size = new System.Drawing.Size(26, 17);
            this.stxt_percent.Text = "0%";
            // 
            // toolStripStatusLabel2
            // 
            this.toolStripStatusLabel2.Name = "toolStripStatusLabel2";
            this.toolStripStatusLabel2.Size = new System.Drawing.Size(48, 17);
            this.toolStripStatusLabel2.Text = "用 时：";
            // 
            // stxt_useTime
            // 
            this.stxt_useTime.Name = "stxt_useTime";
            this.stxt_useTime.Size = new System.Drawing.Size(15, 17);
            this.stxt_useTime.Text = "0";
            // 
            // s_txt_threadlable
            // 
            this.s_txt_threadlable.Name = "s_txt_threadlable";
            this.s_txt_threadlable.Size = new System.Drawing.Size(48, 17);
            this.s_txt_threadlable.Text = "线 程：";
            // 
            // stxt_threadStatus
            // 
            this.stxt_threadStatus.Name = "stxt_threadStatus";
            this.stxt_threadStatus.Size = new System.Drawing.Size(27, 17);
            this.stxt_threadStatus.Text = "0/0";
            // 
            // toolStripStatusLabel6
            // 
            this.toolStripStatusLabel6.Name = "toolStripStatusLabel6";
            this.toolStripStatusLabel6.Size = new System.Drawing.Size(92, 17);
            this.toolStripStatusLabel6.Text = "预计检查队列：";
            // 
            // stxt_threadPoolStatus
            // 
            this.stxt_threadPoolStatus.Name = "stxt_threadPoolStatus";
            this.stxt_threadPoolStatus.Size = new System.Drawing.Size(15, 17);
            this.stxt_threadPoolStatus.Text = "0";
            // 
            // toolStripStatusLabel3
            // 
            this.toolStripStatusLabel3.Name = "toolStripStatusLabel3";
            this.toolStripStatusLabel3.Size = new System.Drawing.Size(68, 17);
            this.toolStripStatusLabel3.Text = "破解成功：";
            // 
            // stxt_crackerSuccessCount
            // 
            this.stxt_crackerSuccessCount.Name = "stxt_crackerSuccessCount";
            this.stxt_crackerSuccessCount.Size = new System.Drawing.Size(15, 17);
            this.stxt_crackerSuccessCount.Text = "0";
            // 
            // toolStripStatusLabel5
            // 
            this.toolStripStatusLabel5.Name = "toolStripStatusLabel5";
            this.toolStripStatusLabel5.Size = new System.Drawing.Size(48, 17);
            this.toolStripStatusLabel5.Text = "速 度：";
            // 
            // stxt_speed
            // 
            this.stxt_speed.Name = "stxt_speed";
            this.stxt_speed.Size = new System.Drawing.Size(15, 17);
            this.stxt_speed.Text = "0";
            // 
            // bt_timer
            // 
            this.bt_timer.Interval = 1000;
            this.bt_timer.Tick += new System.EventHandler(this.bt_timer_Tick);
            // 
            // menuStrip1
            // 
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.tsmi_options,
            this.tsmi_set,
            this.帮助ToolStripMenuItem,
            this.tsmi_tools});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(876, 25);
            this.menuStrip1.TabIndex = 2;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // tsmi_options
            // 
            this.tsmi_options.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.tsmi_options_export,
            this.tsmi_options_import,
            this.tsmi_reloadConfig});
            this.tsmi_options.Name = "tsmi_options";
            this.tsmi_options.Size = new System.Drawing.Size(48, 21);
            this.tsmi_options.Text = "选 项";
            // 
            // tsmi_options_export
            // 
            this.tsmi_options_export.Name = "tsmi_options_export";
            this.tsmi_options_export.Size = new System.Drawing.Size(148, 22);
            this.tsmi_options_export.Text = "导出破解结果";
            this.tsmi_options_export.Click += new System.EventHandler(this.tsmi_options_export_Click);
            // 
            // tsmi_options_import
            // 
            this.tsmi_options_import.Name = "tsmi_options_import";
            this.tsmi_options_import.Size = new System.Drawing.Size(148, 22);
            this.tsmi_options_import.Text = "导入扫描列表";
            this.tsmi_options_import.Click += new System.EventHandler(this.tsmi_options_import_Click);
            // 
            // tsmi_reloadConfig
            // 
            this.tsmi_reloadConfig.Name = "tsmi_reloadConfig";
            this.tsmi_reloadConfig.Size = new System.Drawing.Size(148, 22);
            this.tsmi_reloadConfig.Text = "重新加载配置";
            this.tsmi_reloadConfig.Click += new System.EventHandler(this.tsmi_reloadConfig_Click);
            // 
            // tsmi_set
            // 
            this.tsmi_set.Name = "tsmi_set";
            this.tsmi_set.Size = new System.Drawing.Size(48, 21);
            this.tsmi_set.Text = "设 置";
            this.tsmi_set.Click += new System.EventHandler(this.tsmi_set_Click);
            // 
            // 帮助ToolStripMenuItem
            // 
            this.帮助ToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.tsmi_help_about,
            this.tsmi_help_update,
            this.tsmi_help_version,
            this.tsmi_help_support});
            this.帮助ToolStripMenuItem.Name = "帮助ToolStripMenuItem";
            this.帮助ToolStripMenuItem.Size = new System.Drawing.Size(48, 21);
            this.帮助ToolStripMenuItem.Text = "帮 助";
            // 
            // tsmi_help_about
            // 
            this.tsmi_help_about.Name = "tsmi_help_about";
            this.tsmi_help_about.Size = new System.Drawing.Size(124, 22);
            this.tsmi_help_about.Text = "关 于";
            this.tsmi_help_about.Click += new System.EventHandler(this.tsmi_help_about_Click);
            // 
            // tsmi_help_update
            // 
            this.tsmi_help_update.Name = "tsmi_help_update";
            this.tsmi_help_update.Size = new System.Drawing.Size(124, 22);
            this.tsmi_help_update.Text = "更 新";
            this.tsmi_help_update.Click += new System.EventHandler(this.tsmi_help_update_Click);
            // 
            // tsmi_help_version
            // 
            this.tsmi_help_version.Name = "tsmi_help_version";
            this.tsmi_help_version.Size = new System.Drawing.Size(124, 22);
            this.tsmi_help_version.Text = "版 本";
            this.tsmi_help_version.Click += new System.EventHandler(this.tsmi_help_version_Click);
            // 
            // tsmi_help_support
            // 
            this.tsmi_help_support.Name = "tsmi_help_support";
            this.tsmi_help_support.Size = new System.Drawing.Size(124, 22);
            this.tsmi_help_support.Text = "意见反馈";
            this.tsmi_help_support.Click += new System.EventHandler(this.tsmi_help_support_Click);
            // 
            // tsmi_tools
            // 
            this.tsmi_tools.Name = "tsmi_tools";
            this.tsmi_tools.Size = new System.Drawing.Size(48, 21);
            this.tsmi_tools.Text = "工 具";
            // 
            // toolStripStatusLabel4
            // 
            this.toolStripStatusLabel4.Name = "toolStripStatusLabel4";
            this.toolStripStatusLabel4.Size = new System.Drawing.Size(116, 17);
            this.toolStripStatusLabel4.Text = "剩余端口扫描次数：";
            // 
            // tssl_notScanPortsSumCount
            // 
            this.tssl_notScanPortsSumCount.Name = "tssl_notScanPortsSumCount";
            this.tssl_notScanPortsSumCount.Size = new System.Drawing.Size(15, 17);
            this.tssl_notScanPortsSumCount.Text = "0";
            // 
            // Main
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(876, 677);
            this.Controls.Add(this.rdp_panle);
            this.Controls.Add(this.bt_status);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.menuStrip1);
            this.MainMenuStrip = this.menuStrip1;
            this.Name = "Main";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "超级弱口令检查工具 V1.0 测试版 Beta20 by shack2";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.Main_FormClosing);
            this.Shown += new System.EventHandler(this.Main_Shown);
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.cms_lvw.ResumeLayout(false);
            this.bt_status.ResumeLayout(false);
            this.bt_status.PerformLayout();
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.ListView list_lvw;
        private System.Windows.Forms.ColumnHeader col_id;
        private System.Windows.Forms.ColumnHeader col_ip;
        private System.Windows.Forms.ColumnHeader col_port;
        private System.Windows.Forms.ColumnHeader col_username;
        private System.Windows.Forms.ColumnHeader col_pass;
        private System.Windows.Forms.TextBox txt_target;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button btn_importList;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.ComboBox cbox_threadSize;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.ComboBox cbox_timeOut;
        private System.Windows.Forms.ComboBox cbox_reTry;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Button btn_importUername;
        private System.Windows.Forms.TextBox txt_username;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Button btn_importPassword;
        private System.Windows.Forms.TextBox txt_password;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.Button btn_cracker;
        private System.Windows.Forms.StatusStrip bt_status;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
        private System.Windows.Forms.ToolStripProgressBar tools_proBar;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel2;
        private System.Windows.Forms.ToolStripStatusLabel stxt_useTime;
        private System.Windows.Forms.ToolStripStatusLabel s_txt_threadlable;
        private System.Windows.Forms.ToolStripStatusLabel stxt_threadStatus;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel3;
        private System.Windows.Forms.ToolStripStatusLabel stxt_crackerSuccessCount;
        private System.Windows.Forms.Timer bt_timer;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem tsmi_options;
        private System.Windows.Forms.ToolStripMenuItem tsmi_set;
        private System.Windows.Forms.ToolStripMenuItem 帮助ToolStripMenuItem;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel6;
        private System.Windows.Forms.ToolStripStatusLabel stxt_threadPoolStatus;
        private System.Windows.Forms.ColumnHeader col_serviceName;
        private System.Windows.Forms.ToolStripStatusLabel stxt_percent;
        private System.Windows.Forms.Button btn_stopCracker;
        private System.Windows.Forms.ColumnHeader col_banner;
        private System.Windows.Forms.CheckBox chk_notAutoSelectDic;
        private System.Windows.Forms.CheckBox chk_isScanPort;
        private System.Windows.Forms.CheckBox chk_crackerOneCount;
        private System.Windows.Forms.ToolStripMenuItem tsmi_help_about;
        private System.Windows.Forms.ToolStripMenuItem tsmi_help_update;
        private System.Windows.Forms.ToolStripMenuItem tsmi_options_export;
        private System.Windows.Forms.ToolStripMenuItem tsmi_options_import;
        private System.Windows.Forms.ContextMenuStrip cms_lvw;
        private System.Windows.Forms.ToolStripMenuItem tsmi_export;
        private System.Windows.Forms.ToolStripMenuItem tsmi_deleteSelectItem;
        private System.Windows.Forms.ToolStripMenuItem tsmi_clearItems;
        private System.Windows.Forms.ToolStripMenuItem tsmi_openURL;
        private System.Windows.Forms.ToolStripMenuItem tsmi_copyItem;
        private System.Windows.Forms.ToolStripMenuItem tsmi_help_version;
        private System.Windows.Forms.ToolStripMenuItem tsmi_help_support;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel5;
        private System.Windows.Forms.ToolStripStatusLabel stxt_speed;
        private System.Windows.Forms.TextBox txt_username_ext;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.CheckedListBox services_list;
        private System.Windows.Forms.ToolStripMenuItem tsmi_tools;
        private System.Windows.Forms.RichTextBox txt_log;
        private System.Windows.Forms.Panel rdp_panle;
        private System.Windows.Forms.ToolStripMenuItem tsmi_reloadConfig;
        private System.Windows.Forms.ColumnHeader col_useTime;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel4;
        private System.Windows.Forms.ToolStripStatusLabel tssl_notScanPortsSumCount;
    }
}

