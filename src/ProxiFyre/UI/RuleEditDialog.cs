using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace ProxiFyre;

internal sealed class RuleEditDialog : Window
{
    private readonly TextBox _input;

    private RuleEditDialog(string currentValue)
    {
        Title = "编辑应用规则";
        Owner = System.Windows.Application.Current.MainWindow;
        Width = 460;
        MinHeight = 210;
        MinWidth = 420;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = BrushFromHex("#F3F6FA");

        var root = new Grid
        {
            Margin = new Thickness(16)
        };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var label = new TextBlock
        {
            Text = "应用规则",
            FontWeight = FontWeights.SemiBold,
            Foreground = BrushFromHex("#1F2937")
        };
        root.Children.Add(label);

        _input = new TextBox
        {
            Text = currentValue,
            MinHeight = 32,
            Margin = new Thickness(0, 8, 0, 6),
            Padding = new Thickness(9, 5, 9, 5),
            VerticalContentAlignment = VerticalAlignment.Center
        };
        _input.SelectAll();
        _input.KeyDown += Input_KeyDown;
        Grid.SetRow(_input, 1);
        root.Children.Add(_input);

        var hint = new TextBlock
        {
            Text = "例如 chrome.exe、完整 exe 路径，或目录路径。",
            FontSize = 12,
            Foreground = BrushFromHex("#667085")
        };
        Grid.SetRow(hint, 2);
        root.Children.Add(hint);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 14, 0, 0)
        };

        var cancel = new Button
        {
            Content = "取消",
            MinWidth = 72,
            Background = BrushFromHex("#EEF2F7"),
            Foreground = BrushFromHex("#1F2937"),
            Margin = new Thickness(0, 0, 8, 0)
        };
        cancel.Click += (_, _) => DialogResult = false;
        buttons.Children.Add(cancel);

        var confirm = new Button
        {
            Content = "保存",
            MinWidth = 72,
            Background = BrushFromHex("#2563EB"),
            Foreground = Brushes.White
        };
        confirm.Click += (_, _) => Confirm();
        buttons.Children.Add(confirm);

        Grid.SetRow(buttons, 3);
        root.Children.Add(buttons);

        Content = root;
        Loaded += (_, _) => _input.Focus();
    }

    public string RuleText => _input.Text.Trim();

    public static string? Show(Window owner, string currentValue)
    {
        var dialog = new RuleEditDialog(currentValue)
        {
            Owner = owner
        };

        return dialog.ShowDialog() == true
            ? dialog.RuleText
            : null;
    }

    private void Input_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            Confirm();
        }
    }

    private void Confirm()
    {
        if (string.IsNullOrWhiteSpace(_input.Text))
        {
            MessageBox.Show(this, "请输入应用规则。", "ProxiFyre", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        DialogResult = true;
    }

    private static SolidColorBrush BrushFromHex(string value)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
        brush.Freeze();
        return brush;
    }
}
