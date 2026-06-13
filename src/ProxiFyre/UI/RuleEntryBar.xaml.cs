using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace ProxiFyre;

public partial class RuleEntryBar : UserControl
{
    public RuleEntryBar()
    {
        InitializeComponent();
    }

    public event EventHandler<TextRequestedEventArgs>? AddRuleRequested;

    public event EventHandler? BrowseApplicationRequested;

    public event EventHandler? BrowseDirectoryRequested;

    public event EventHandler? CoreProcessNameChanged;

    public string CoreProcessName
    {
        get => CoreProcessNameInput.Text;
        set => CoreProcessNameInput.Text = value;
    }

    public void NormalizeCoreProcessName()
    {
        CoreProcessNameInput.Text = AppConfiguration.NormalizeCoreProcessName(CoreProcessNameInput.Text);
    }

    private void AddButton_Click(object sender, RoutedEventArgs e)
    {
        var value = AppInput.Text.Trim();
        AddRuleRequested?.Invoke(this, new TextRequestedEventArgs(value));
        AppInput.Clear();
    }

    private void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        BrowseApplicationRequested?.Invoke(this, EventArgs.Empty);
    }

    private void BrowseDirectoryButton_Click(object sender, RoutedEventArgs e)
    {
        BrowseDirectoryRequested?.Invoke(this, EventArgs.Empty);
    }

    private void CoreProcessNameInput_LostFocus(object sender, RoutedEventArgs e)
    {
        CoreProcessNameChanged?.Invoke(this, EventArgs.Empty);
    }

    private void CoreProcessNameInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter)
        {
            return;
        }

        e.Handled = true;
        CoreProcessNameChanged?.Invoke(this, EventArgs.Empty);
        Keyboard.ClearFocus();
    }
}
