namespace SNETCracker
{
    partial class Seting
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle2 = new System.Windows.Forms.DataGridViewCellStyle();
            this.ds_servicesConfig = new System.Windows.Forms.DataGridView();
            this.col_index = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.ServiceName = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.ports = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.保存 = new System.Windows.Forms.Button();
            this.btn_reload = new System.Windows.Forms.Button();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.tvw_dicpaths = new System.Windows.Forms.TreeView();
            this.txt_dicPath = new System.Windows.Forms.TextBox();
            this.btn_update = new System.Windows.Forms.Button();
            this.txt_passList = new System.Windows.Forms.TextBox();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.btn_orcl_update = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.txt_orcl = new System.Windows.Forms.TextBox();
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.tsmi_deleteSelect = new System.Windows.Forms.ToolStripMenuItem();
            this.tsmi_openDic = new System.Windows.Forms.ToolStripMenuItem();
            ((System.ComponentModel.ISupportInitialize)(this.ds_servicesConfig)).BeginInit();
            this.tabControl1.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            this.tabPage3.SuspendLayout();
            this.contextMenuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // ds_servicesConfig
            // 
            this.ds_servicesConfig.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.ds_servicesConfig.BackgroundColor = System.Drawing.SystemColors.ButtonHighlight;
            dataGridViewCellStyle2.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleCenter;
            dataGridViewCellStyle2.BackColor = System.Drawing.SystemColors.Control;
            dataGridViewCellStyle2.Font = new System.Drawing.Font("宋体", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            dataGridViewCellStyle2.ForeColor = System.Drawing.SystemColors.WindowText;
            dataGridViewCellStyle2.SelectionBackColor = System.Drawing.SystemColors.Highlight;
            dataGridViewCellStyle2.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle2.WrapMode = System.Windows.Forms.DataGridViewTriState.True;
            this.ds_servicesConfig.ColumnHeadersDefaultCellStyle = dataGridViewCellStyle2;
            this.ds_servicesConfig.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.ds_servicesConfig.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.col_index,
            this.ServiceName,
            this.ports});
            this.ds_servicesConfig.Cursor = System.Windows.Forms.Cursors.Default;
            this.ds_servicesConfig.GridColor = System.Drawing.SystemColors.ActiveBorder;
            this.ds_servicesConfig.Location = new System.Drawing.Point(3, 17);
            this.ds_servicesConfig.Name = "ds_servicesConfig";
            this.ds_servicesConfig.RowTemplate.Height = 23;
            this.ds_servicesConfig.Size = new System.Drawing.Size(503, 506);
            this.ds_servicesConfig.TabIndex = 0;
            // 
            // col_index
            // 
            this.col_index.Frozen = true;
            this.col_index.HeaderText = "序号";
            this.col_index.Name = "col_index";
            this.col_index.ReadOnly = true;
            this.col_index.Width = 60;
            // 
            // ServiceName
            // 
            this.ServiceName.Frozen = true;
            this.ServiceName.HeaderText = "服务";
            this.ServiceName.Name = "ServiceName";
            this.ServiceName.Width = 150;
            // 
            // ports
            // 
            this.ports.HeaderText = "端口";
            this.ports.Name = "ports";
            this.ports.Width = 200;
            // 
            // 保存
            // 
            this.保存.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.保存.Location = new System.Drawing.Point(285, 20);
            this.保存.Name = "保存";
            this.保存.Size = new System.Drawing.Size(114, 23);
            this.保存.TabIndex = 1;
            this.保存.Text = "保 存";
            this.保存.UseVisualStyleBackColor = true;
            this.保存.Click += new System.EventHandler(this.保存_Click);
            // 
            // btn_reload
            // 
            this.btn_reload.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.btn_reload.Location = new System.Drawing.Point(83, 20);
            this.btn_reload.Name = "btn_reload";
            this.btn_reload.Size = new System.Drawing.Size(107, 23);
            this.btn_reload.TabIndex = 1;
            this.btn_reload.Text = "重新加载";
            this.btn_reload.UseVisualStyleBackColor = true;
            this.btn_reload.Click += new System.EventHandler(this.btn_reload_Click);
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Controls.Add(this.tabPage3);
            this.tabControl1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControl1.Location = new System.Drawing.Point(0, 0);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(523, 613);
            this.tabControl1.TabIndex = 2;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.groupBox2);
            this.tabPage1.Controls.Add(this.groupBox1);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(515, 587);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "服务端口设置";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.btn_reload);
            this.groupBox2.Controls.Add(this.保存);
            this.groupBox2.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.groupBox2.Location = new System.Drawing.Point(3, 526);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(509, 58);
            this.groupBox2.TabIndex = 3;
            this.groupBox2.TabStop = false;
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.ds_servicesConfig);
            this.groupBox1.Cursor = System.Windows.Forms.Cursors.No;
            this.groupBox1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.groupBox1.Location = new System.Drawing.Point(3, 3);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(509, 581);
            this.groupBox1.TabIndex = 2;
            this.groupBox1.TabStop = false;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.splitContainer1);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(515, 587);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "字典设置";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // splitContainer1
            // 
            this.splitContainer1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer1.Location = new System.Drawing.Point(3, 3);
            this.splitContainer1.Name = "splitContainer1";
            // 
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.tvw_dicpaths);
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.txt_dicPath);
            this.splitContainer1.Panel2.Controls.Add(this.btn_update);
            this.splitContainer1.Panel2.Controls.Add(this.txt_passList);
            this.splitContainer1.Size = new System.Drawing.Size(509, 581);
            this.splitContainer1.SplitterDistance = 218;
            this.splitContainer1.TabIndex = 0;
            // 
            // tvw_dicpaths
            // 
            this.tvw_dicpaths.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tvw_dicpaths.Location = new System.Drawing.Point(0, 0);
            this.tvw_dicpaths.Name = "tvw_dicpaths";
            this.tvw_dicpaths.Size = new System.Drawing.Size(218, 581);
            this.tvw_dicpaths.TabIndex = 0;
            this.tvw_dicpaths.DoubleClick += new System.EventHandler(this.tvw_dicpaths_DoubleClick);
            // 
            // txt_dicPath
            // 
            this.txt_dicPath.Location = new System.Drawing.Point(3, 555);
            this.txt_dicPath.Name = "txt_dicPath";
            this.txt_dicPath.Size = new System.Drawing.Size(198, 21);
            this.txt_dicPath.TabIndex = 2;
            // 
            // btn_update
            // 
            this.btn_update.Anchor = System.Windows.Forms.AnchorStyles.Bottom;
            this.btn_update.Location = new System.Drawing.Point(207, 553);
            this.btn_update.Name = "btn_update";
            this.btn_update.Size = new System.Drawing.Size(75, 23);
            this.btn_update.TabIndex = 1;
            this.btn_update.Text = "更新字典";
            this.btn_update.UseVisualStyleBackColor = true;
            this.btn_update.Click += new System.EventHandler(this.btn_update_Click);
            // 
            // txt_passList
            // 
            this.txt_passList.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txt_passList.Location = new System.Drawing.Point(3, 3);
            this.txt_passList.Multiline = true;
            this.txt_passList.Name = "txt_passList";
            this.txt_passList.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txt_passList.Size = new System.Drawing.Size(279, 544);
            this.txt_passList.TabIndex = 0;
            // 
            // tabPage3
            // 
            this.tabPage3.Controls.Add(this.btn_orcl_update);
            this.tabPage3.Controls.Add(this.label1);
            this.tabPage3.Controls.Add(this.txt_orcl);
            this.tabPage3.Location = new System.Drawing.Point(4, 22);
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage3.Size = new System.Drawing.Size(515, 587);
            this.tabPage3.TabIndex = 2;
            this.tabPage3.Text = "Oracle监听名称";
            this.tabPage3.UseVisualStyleBackColor = true;
            // 
            // btn_orcl_update
            // 
            this.btn_orcl_update.Location = new System.Drawing.Point(379, 25);
            this.btn_orcl_update.Name = "btn_orcl_update";
            this.btn_orcl_update.Size = new System.Drawing.Size(75, 23);
            this.btn_orcl_update.TabIndex = 2;
            this.btn_orcl_update.Text = "更 新";
            this.btn_orcl_update.UseVisualStyleBackColor = true;
            this.btn_orcl_update.Click += new System.EventHandler(this.btn_orcl_update_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(25, 28);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(65, 12);
            this.label1.TabIndex = 1;
            this.label1.Text = "监听名称：";
            // 
            // txt_orcl
            // 
            this.txt_orcl.Location = new System.Drawing.Point(96, 25);
            this.txt_orcl.Name = "txt_orcl";
            this.txt_orcl.Size = new System.Drawing.Size(257, 21);
            this.txt_orcl.TabIndex = 0;
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.tsmi_deleteSelect,
            this.tsmi_openDic});
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(153, 70);
            // 
            // tsmi_deleteSelect
            // 
            this.tsmi_deleteSelect.Name = "tsmi_deleteSelect";
            this.tsmi_deleteSelect.Size = new System.Drawing.Size(124, 22);
            this.tsmi_deleteSelect.Text = "删除选中";
            this.tsmi_deleteSelect.Click += new System.EventHandler(this.tsmi_deleteSelect_Click);
            // 
            // tsmi_openDic
            // 
            this.tsmi_openDic.Name = "tsmi_openDic";
            this.tsmi_openDic.Size = new System.Drawing.Size(152, 22);
            this.tsmi_openDic.Text = "打开字典";
            this.tsmi_openDic.Click += new System.EventHandler(this.tsmi_openDic_Click);
            // 
            // Seting
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(523, 613);
            this.Controls.Add(this.tabControl1);
            this.Name = "Seting";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "设 置";
            this.Shown += new System.EventHandler(this.Seting_Shown);
            ((System.ComponentModel.ISupportInitialize)(this.ds_servicesConfig)).EndInit();
            this.tabControl1.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.groupBox2.ResumeLayout(false);
            this.groupBox1.ResumeLayout(false);
            this.tabPage2.ResumeLayout(false);
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel2.ResumeLayout(false);
            this.splitContainer1.Panel2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            this.tabPage3.ResumeLayout(false);
            this.tabPage3.PerformLayout();
            this.contextMenuStrip1.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.DataGridView ds_servicesConfig;
        private System.Windows.Forms.Button 保存;
        private System.Windows.Forms.Button btn_reload;
        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.TreeView tvw_dicpaths;
        private System.Windows.Forms.TabPage tabPage3;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txt_orcl;
        private System.Windows.Forms.Button btn_orcl_update;
        private System.Windows.Forms.Button btn_update;
        private System.Windows.Forms.TextBox txt_passList;
        private System.Windows.Forms.TextBox txt_dicPath;
        private System.Windows.Forms.DataGridViewTextBoxColumn col_index;
        private System.Windows.Forms.DataGridViewTextBoxColumn ServiceName;
        private System.Windows.Forms.DataGridViewTextBoxColumn ports;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ToolStripMenuItem tsmi_deleteSelect;
        private System.Windows.Forms.ToolStripMenuItem tsmi_openDic;
    }
}