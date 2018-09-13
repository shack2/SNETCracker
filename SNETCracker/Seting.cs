using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Tools;

namespace SNETCracker
{
    public partial class Seting : Form
    {
        public Seting()
        {
            InitializeComponent();
        }

        private String baseServicePath = Directory.GetCurrentDirectory() + "/config/servicesnames.txt";
        private String basePortsPath = Directory.GetCurrentDirectory() + "/config/servicesports.txt";
        private String baseOraclePath = Directory.GetCurrentDirectory() + "/config/oracle.txt";
        private void loadServerPort(String servicesNamesStr,String servicesPortsStr) { 
            String[] servicesName = servicesNamesStr.Split(':');
            String[] servicesPort = servicesPortsStr.Split(':');
            DataGridViewRow row = new DataGridViewRow();

            for (int i = 0; i < servicesName.Length; i++)
            {
                int index = this.ds_servicesConfig.Rows.Add();
                this.ds_servicesConfig.Rows[index].Cells[0].ReadOnly = true;
                this.ds_servicesConfig.Rows[index].Cells[1].ReadOnly = true;
                this.ds_servicesConfig.Rows[index].Cells[0].Value = i+1;
                this.ds_servicesConfig.Rows[index].Cells[1].Value = servicesName[i];
                this.ds_servicesConfig.Rows[index].Cells[2].Value = servicesPort[i];
            }
        }

        private void Seting_Shown(object sender, EventArgs e)
        {
            String orcl_name = FileTool.readFileToString(baseOraclePath);
            this.txt_orcl.Text = orcl_name;
            String servicesNamesStr = FileTool.readFileToString(baseServicePath);
            String servicesPortsStr = FileTool.readFileToString(basePortsPath);
            loadServerPort(servicesNamesStr, servicesPortsStr);
            loadDics(servicesNamesStr);
        }

        private void btn_reload_Click(object sender, EventArgs e)
        {
            this.ds_servicesConfig.Rows.Clear();
            String servicesNamesStr = FileTool.readFileToString(baseServicePath);
            String servicesPortsStr = FileTool.readFileToString(basePortsPath);
            loadServerPort(servicesNamesStr, servicesPortsStr);

        }

        private void loadDics(String servicesName)
        {
            List<String> list = FileTool.readAllDic(Directory.GetCurrentDirectory() + "/dic/");
            TreeNode usertn = new TreeNode("用户名字典");
            TreeNode passtn = new TreeNode("密码字典");
            String[] servicesNames = servicesName.Split(':');

            foreach (String dic in servicesNames) {
                TreeNode tn = new TreeNode();
                tn.Text=dic;
                TreeNode tn_username = new TreeNode();
                tn_username.Text = "dic_username_" + dic.ToLower().Replace("_ssl", "") + ".txt";

                TreeNode tn_pass = new TreeNode();
                tn_pass.Text = "dic_password_" + dic.ToLower().Replace("_ssl", "") + ".txt";

                tn.Nodes.Add(tn_username);
                tn.Nodes.Add(tn_pass);
                tn.ExpandAll();
                this.tvw_dicpaths.Nodes.Add(tn);
            }
            this.tvw_dicpaths.ExpandAll();
        }

        private void 保存_Click(object sender, EventArgs e)
        {
            try
            {
                StringBuilder serviceNames = new StringBuilder();
                StringBuilder servicePorts = new StringBuilder();
                foreach (DataGridViewRow dvr in this.ds_servicesConfig.Rows)
                {

                    if (dvr.Cells[1].Value != null)
                    {
                        serviceNames.Append(dvr.Cells[1].Value + ":");
                        servicePorts.Append(dvr.Cells[2].Value + ":");
                    }
                }
                FileTool.WriteStringToFile(baseServicePath, serviceNames.Remove(serviceNames.Length - 1, 1).ToString());
                FileTool.WriteStringToFile(basePortsPath, servicePorts.Remove(servicePorts.Length - 1, 1).ToString());
                MessageBox.Show("保存成功！");
            }
            catch (Exception ex) {
                MessageBox.Show("保存发生异常！" + ex.Message);
            }
        }

        private void btn_orcl_update_Click(object sender, EventArgs e)
        {
           if (String.IsNullOrEmpty(this.txt_orcl.Text))
           {
                MessageBox.Show("监听名为空！");
                return;
           }
           FileTool.WriteStringToFile(baseOraclePath, this.txt_orcl.Text);
           MessageBox.Show("成功！");
        }

        private void btn_update_Click(object sender, EventArgs e)
        {
            if (String.IsNullOrEmpty(this.txt_dicPath.Text))
            {
                MessageBox.Show("字典路径为空！");
                return;
            }
            if (String.IsNullOrEmpty(this.txt_passList.Text))
            {
                MessageBox.Show("密码字典为空！");
                return;
            }
            this.btn_update.Enabled = false;
            Thread th = new Thread(updateDic);
            th.Start();
        }
        private void updateDic() {
            try
            {
                String txts = this.txt_passList.Text;
                String[] lines = Regex.Split(txts, "\\r\\n");
                HashSet<string> hs = new HashSet<string>();
                foreach (String line in lines)
                {
                    if (!hs.Contains(line))
                    {
                        hs.Add(line);
                    }
                }
                FileTool.WriteStringToFile(this.txt_dicPath.Text, hs);
                MessageBox.Show("更新成功！");
            }
            catch (Exception e) {
                MessageBox.Show("更新字典发生异常！"+e.Message);
            }
            this.btn_update.Enabled = true;
        }

        private void tsmi_deleteSelect_Click(object sender, EventArgs e)
        {
            if (this.ds_servicesConfig.SelectedRows.Count > 0)
            {
                this.ds_servicesConfig.Rows.Remove(this.ds_servicesConfig.SelectedRows[0]);
            }
        }

        private void openDic() {
            if (this.tvw_dicpaths.SelectedNode != null && this.tvw_dicpaths.SelectedNode.Text.StartsWith("dic"))
            {
                String path = Directory.GetCurrentDirectory() + "\\dic\\" + this.tvw_dicpaths.SelectedNode.Text;
                this.txt_dicPath.Text = path;
                HashSet<String> list = FileTool.readFileToList(path);
                this.txt_passList.Clear();
                foreach (String pass in list)
                {
                    this.txt_passList.AppendText(pass + "\r\n");
                }

            }
        }

        private void tvw_dicpaths_DoubleClick(object sender, EventArgs e)
        {
            openDic();
        }

        private void tsmi_openDic_Click(object sender, EventArgs e)
        {
            openDic();
        }
    }
}
