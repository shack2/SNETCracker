using Avalonia.Controls;
using SPasswordCheckerV2.ViewModels;

namespace SPasswordCheckerV2.Views
{
    public partial class UpdateWindow : Window
    {
        public UpdateWindow()
        {
            InitializeComponent();
            Opened += (s, e) =>
            {
                var vm = DataContext as UpdateViewModel;
                if (vm == null) return;
                // 启动自动检测已命中更新：直接下载；手动打开：先检查更新
                if (vm.AutoDownload) vm.UpdateDataCommand.Execute(null);
                else vm.GetNewVersionCommand.Execute(null);
            };
        }
    }
}
