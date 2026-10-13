using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Tools;

namespace SPasswordCheckerV2.Views
{
    /// <summary>
    /// 问题反馈窗口：在线提交到 SoftUpdate 更新服务（POST /api/client/feedback，
    /// 自动携带应用标识与当前版本号，AES 令牌鉴权）；未配置服务或网络异常时提示邮箱渠道。
    /// </summary>
    public partial class FeedbackWindow : Window
    {
        private bool sending;

        public FeedbackWindow()
        {
            InitializeComponent();
        }

        private void OnCancel(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async void OnSubmit(object sender, RoutedEventArgs e)
        {
            if (sending)
            {
                return;
            }
            string content = contentBox.Text == null ? "" : contentBox.Text.Trim();
            if (content.Length == 0)
            {
                ShowStatus("请填写反馈内容", true);
                return;
            }
            sending = true;
            submitBtn.IsEnabled = false;
            ShowStatus("正在提交...", false);
            try
            {
                var cfg = SoftUpdateConfig.Load(AppContext.BaseDirectory + "/config/update.ini");
                var client = new SoftUpdateClient(cfg, SoftUpdateClient.GetAssemblyVersion());
                await client.SubmitFeedbackAsync(content, contactBox.Text);
                Close();
                Msg.Show("反馈已提交，感谢您的建议！");
            }
            catch (Exception ex)
            {
                ShowStatus("提交失败：" + ex.Message + "（也可邮件反馈：1341413415@qq.com）", true);
                submitBtn.IsEnabled = true;
                sending = false;
            }
        }

        private void ShowStatus(string text, bool isError)
        {
            statusText.Text = text;
            string key = isError ? "AppDangerFg" : "AppTextSecondary";
            if (this.TryFindResource(key, out object res) && res is IBrush brush)
            {
                statusText.Foreground = brush;
            }
        }
    }
}
