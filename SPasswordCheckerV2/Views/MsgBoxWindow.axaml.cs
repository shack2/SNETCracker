using System.Threading.Tasks;
using Avalonia.Controls;

namespace SPasswordCheckerV2.Views
{
    /// <summary>自建消息对话框（替代 Ursa MessageBox），模态、支持 OK / OKCancel 两种模式</summary>
    public partial class MsgBoxWindow : Window
    {
        private bool confirmed;

        public MsgBoxWindow()
        {
            InitializeComponent();
        }

        private MsgBoxWindow(string title, string message, bool confirm) : this()
        {
            Title = title;
            titleText.Text = title;
            messageText.Text = message;
            cancelBtn.IsVisible = confirm;
            // Enter/Esc 快捷关闭
            KeyBindings.Add(new Avalonia.Input.KeyBinding
            {
                Gesture = new Avalonia.Input.KeyGesture(Avalonia.Input.Key.Enter),
                Command = new RelayCloseCommand(this, true)
            });
            KeyBindings.Add(new Avalonia.Input.KeyBinding
            {
                Gesture = new Avalonia.Input.KeyGesture(Avalonia.Input.Key.Escape),
                Command = new RelayCloseCommand(this, false)
            });
        }

        private void OnOk(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            confirmed = true;
            Close();
        }

        private void OnCancel(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            confirmed = false;
            Close();
        }

        public static async Task ShowAsync(Window owner, string title, string message)
        {
            var dlg = new MsgBoxWindow(title, message, false);
            if (owner != null)
            {
                await dlg.ShowDialog(owner);
            }
            else
            {
                dlg.Show();
            }
        }

        public static async Task<bool> ConfirmAsync(Window owner, string title, string message)
        {
            var dlg = new MsgBoxWindow(title, message, true);
            if (owner != null)
            {
                await dlg.ShowDialog(owner);
                return dlg.confirmed;
            }
            dlg.Show();
            return false;
        }

        /// <summary>简单的关闭命令（Enter=确定 / Esc=取消）</summary>
        private sealed class RelayCloseCommand : System.Windows.Input.ICommand
        {
            private readonly MsgBoxWindow dlg;
            private readonly bool ok;

            public RelayCloseCommand(MsgBoxWindow dlg, bool ok)
            {
                this.dlg = dlg;
                this.ok = ok;
            }

            public event System.EventHandler CanExecuteChanged { add { } remove { } }

            public bool CanExecute(object parameter) => true;

            public void Execute(object parameter)
            {
                dlg.confirmed = ok;
                dlg.Close();
            }
        }
    }
}
