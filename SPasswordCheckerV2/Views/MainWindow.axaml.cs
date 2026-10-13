using Avalonia.Controls;
using Avalonia.Interactivity;
using SPasswordCheckerV2.ViewModels;

namespace SPasswordCheckerV2.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            DataContextChanged += (s, e) =>
            {
                if (DataContext is MainViewModel vm)
                {
                    vm.MainWindow = this;
                }
            };
            Opened += (s, e) =>
            {
                (DataContext as MainViewModel)?.GetNewVersionCommand.Execute(null);
            };
        }

        private void OnSideAllSelected(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                foreach (var s in vm.ListServies)
                {
                    s.IsChecked = true;
                }
            }
        }

        private void OnSideClearSelected(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                foreach (var s in vm.ListServies)
                {
                    s.IsChecked = false;
                }
            }
        }

        private void OnToggleLog(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                vm.IsLogExpanded = !vm.IsLogExpanded;
            }
        }

        private void OnCheckListSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (DataContext is MainViewModel vm && sender is TableView tv)
            {
                vm.SelectedCheckResults = tv.SelectedItems;
            }
        }
    }
}
