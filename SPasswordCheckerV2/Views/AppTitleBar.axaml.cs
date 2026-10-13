using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;

namespace SPasswordCheckerV2.Views
{
    /// <summary>
    /// 自建窗口标题栏（替代 UrsaWindow 铬）。宿主 Window 需设置
    /// ExtendClientAreaToDecorationsHint=True + ExtendClientAreaChromeHints=NoChrome，
    /// 本控件提供拖拽移动、双击最大化切换、最小化/最大化/关闭按钮。
    /// </summary>
    public partial class AppTitleBar : UserControl
    {
        public static readonly StyledProperty<object> LeftContentProperty =
            AvaloniaProperty.Register<AppTitleBar, object>(nameof(LeftContent));

        public static readonly StyledProperty<object> RightContentProperty =
            AvaloniaProperty.Register<AppTitleBar, object>(nameof(RightContent));

        public static readonly StyledProperty<bool> ShowMinimizeProperty =
            AvaloniaProperty.Register<AppTitleBar, bool>(nameof(ShowMinimize), true);

        public static readonly StyledProperty<bool> ShowMaximizeProperty =
            AvaloniaProperty.Register<AppTitleBar, bool>(nameof(ShowMaximize), true);

        /// <summary>标题栏底色；null 时回退主题资源 AppHeaderBg（弹窗可设 AppMsgTitleBg 形成层次）。</summary>
        public static readonly StyledProperty<Avalonia.Media.IBrush> BarBackgroundProperty =
            AvaloniaProperty.Register<AppTitleBar, Avalonia.Media.IBrush>(nameof(BarBackground));

        public Avalonia.Media.IBrush BarBackground
        {
            get => GetValue(BarBackgroundProperty);
            set => SetValue(BarBackgroundProperty, value);
        }

        public object LeftContent
        {
            get => GetValue(LeftContentProperty);
            set => SetValue(LeftContentProperty, value);
        }

        public object RightContent
        {
            get => GetValue(RightContentProperty);
            set => SetValue(RightContentProperty, value);
        }

        public bool ShowMinimize
        {
            get => GetValue(ShowMinimizeProperty);
            set => SetValue(ShowMinimizeProperty, value);
        }

        public bool ShowMaximize
        {
            get => GetValue(ShowMaximizeProperty);
            set => SetValue(ShowMaximizeProperty, value);
        }

        public AppTitleBar()
        {
            InitializeComponent();
        }

        protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
        {
            base.OnPropertyChanged(change);
            // BarBackground 非空时置为本地值覆写样式默认底色；为空时清掉本地值回退样式（AppHeaderBg）
            if (change.Property == BarBackgroundProperty)
            {
                var brush = change.GetNewValue<Avalonia.Media.IBrush>();
                if (brush != null)
                {
                    PART_Drag.Background = brush;
                }
                else
                {
                    PART_Drag.ClearValue(Border.BackgroundProperty);
                }
            }
        }

        private Window HostWindow => TopLevel.GetTopLevel(this) as Window;

        private void OnDragPointerPressed(object sender, PointerPressedEventArgs e)
        {
            // 左键按下开始拖拽移动窗口（点击标题栏按钮时事件已被按钮处理，不会冒泡到这里）
            if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            {
                HostWindow?.BeginMoveDrag(e);
            }
        }

        private void OnDragDoubleTapped(object sender, TappedEventArgs e)
        {
            if (ShowMaximize)
            {
                ToggleMaximize();
            }
        }

        private void ToggleMaximize()
        {
            var w = HostWindow;
            if (w != null)
            {
                w.WindowState = w.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            }
        }

        private void OnMinimize(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var w = HostWindow;
            if (w != null)
            {
                w.WindowState = WindowState.Minimized;
            }
        }

        private void OnToggleMaximize(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            ToggleMaximize();
        }

        private void OnClose(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            HostWindow?.Close();
        }
    }
}
