using CommunityToolkit.Mvvm.ComponentModel;
using System;

namespace SPasswordCheckerV2.Data
{
    public partial class Service : ObservableObject
    {
        public Service()
        {

        }

        public Service(string ServiceName, int[] Ports)
        {
            this.ServiceName = ServiceName;
            this.Ports = Ports;
        }

        public string ServiceName { get; set; }

        public int[] Ports { get; set; }

        /// <summary>左侧服务列表勾选状态</summary>
        [ObservableProperty]
        private bool isChecked;

        /// <summary>端口列可编辑文本（逗号分隔），用于配置窗口双向编辑</summary>
        public string PortsText
        {
            get { return Ports == null ? "" : string.Join(",", Ports); }
            set
            {
                try
                {
                    Ports = Array.ConvertAll(value.Split(',', StringSplitOptions.RemoveEmptyEntries), s => int.Parse(s.Trim()));
                }
                catch
                {
                    // 输入不合法时保留原值
                }
            }
        }
    }
}
