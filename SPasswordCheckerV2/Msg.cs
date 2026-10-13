using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using System.Threading.Tasks;

namespace SPasswordCheckerV2
{
    /// <summary>
    /// 消息提示封装（替代原 CPF MessageBox），统一走自建 MsgBoxWindow，
    /// 并保证在 UI 线程调用，方便后续 API 变化时只改这一处。
    /// </summary>
    public static class Msg
    {
        private static Avalonia.Controls.Window GetActiveWindow()
        {
            return (Avalonia.Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;
        }

        public static void Show(string message, string title = "提示")
        {
            Dispatcher.UIThread.Post(async () =>
            {
                await Views.MsgBoxWindow.ShowAsync(GetActiveWindow(), title, message);
            });
        }

        public static Task<bool> ConfirmAsync(string message, string title = "提示")
        {
            var tcs = new TaskCompletionSource<bool>();
            Dispatcher.UIThread.Post(async () =>
            {
                bool ok = await Views.MsgBoxWindow.ConfirmAsync(GetActiveWindow(), title, message);
                tcs.SetResult(ok);
            });
            return tcs.Task;
        }
    }
}
