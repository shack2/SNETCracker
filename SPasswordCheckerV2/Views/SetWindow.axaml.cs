using Avalonia.Controls;
using SPasswordCheckerV2.ViewModels;

namespace SPasswordCheckerV2.Views
{
    public partial class SetWindow : Window
    {
        public SetWindow()
        {
            InitializeComponent();
        }

        private void OnPortEditorLostFocus(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            //端口编辑框失焦后自动保存（保持原有行为）
            (DataContext as SetViewModel)?.SaveSevicesCommand.Execute(null);
        }
    }
}
