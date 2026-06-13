using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace ProxiFyre;

internal sealed class RegistrationDialog : Window
{
    private readonly string _deviceId;
    private readonly TextBox _keyInput;

    private RegistrationDialog(string deviceId, string? currentKey)
    {
        _deviceId = deviceId;
        Title = "注册 ProxiFyre";
        Owner = System.Windows.Application.Current.MainWindow;
        Width = 520;
        MinWidth = 460;
        MinHeight = 300;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F3F6FA"));

        var root = new Grid
        {
            Margin = new Thickness(18)
        };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var title = new TextBlock
        {
            Text = "需要注册后才能启用核心",
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Foreground = BrushFromHex("#111827")
        };
        root.Children.Add(title);

        var subtitle = new TextBlock
        {
            Text = "请复制当前设备码，并输入对应注册码。",
            Margin = new Thickness(0, 6, 0, 16),
            Foreground = BrushFromHex("#667085")
        };
        Grid.SetRow(subtitle, 1);
        root.Children.Add(subtitle);

        var deviceLabel = new TextBlock
        {
            Text = "当前设备码",
            FontWeight = FontWeights.SemiBold,
            Foreground = BrushFromHex("#1F2937")
        };
        Grid.SetRow(deviceLabel, 2);
        root.Children.Add(deviceLabel);

        var deviceRow = new Grid
        {
            Margin = new Thickness(0, 8, 0, 14)
        };
        deviceRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        deviceRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var deviceInput = new TextBox
        {
            Text = deviceId,
            IsReadOnly = true,
            MinHeight = 34,
            Padding = new Thickness(9, 6, 9, 6),
            VerticalContentAlignment = VerticalAlignment.Center
        };
        deviceRow.Children.Add(deviceInput);

        var copyButton = new Button
        {
            Content = "复制",
            MinWidth = 72,
            Margin = new Thickness(8, 0, 0, 0),
            Background = BrushFromHex("#EEF2F7"),
            Foreground = BrushFromHex("#1F2937")
        };
        copyButton.Click += (_, _) =>
        {
            Clipboard.SetText(_deviceId);
            copyButton.Content = "已复制";
        };
        Grid.SetColumn(copyButton, 1);
        deviceRow.Children.Add(copyButton);

        Grid.SetRow(deviceRow, 3);
        root.Children.Add(deviceRow);

        var keyLabel = new TextBlock
        {
            Text = "注册码",
            FontWeight = FontWeights.SemiBold,
            Foreground = BrushFromHex("#1F2937")
        };
        Grid.SetRow(keyLabel, 4);
        root.Children.Add(keyLabel);

        var keyArea = new StackPanel
        {
            Margin = new Thickness(0, 8, 0, 0)
        };

        _keyInput = new TextBox
        {
            Text = currentKey ?? string.Empty,
            MinHeight = 34,
            Padding = new Thickness(9, 6, 9, 6),
            VerticalContentAlignment = VerticalAlignment.Center
        };
        _keyInput.SelectAll();
        _keyInput.KeyDown += Input_KeyDown;
        keyArea.Children.Add(_keyInput);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 16, 0, 0)
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
            Content = "确定",
            MinWidth = 72,
            Background = BrushFromHex("#2563EB"),
            Foreground = Brushes.White
        };
        confirm.Click += (_, _) => Confirm();
        buttons.Children.Add(confirm);
        keyArea.Children.Add(buttons);

        Grid.SetRow(keyArea, 5);
        root.Children.Add(keyArea);

        Content = root;
        Loaded += (_, _) => _keyInput.Focus();
    }

    public string KeyText => _keyInput.Text.Trim();

    public static string? Show(Window owner, string deviceId, string? currentKey)
    {
        var dialog = new RegistrationDialog(deviceId, currentKey)
        {
            Owner = owner
        };

        return dialog.ShowDialog() == true
            ? dialog.KeyText
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
        if (!LicenseKey.IsValid(_deviceId, _keyInput.Text))
        {
            MessageBox.Show(this, "注册码无效。", "ProxiFyre", MessageBoxButton.OK, MessageBoxImage.Warning);
            _keyInput.Focus();
            _keyInput.SelectAll();
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
