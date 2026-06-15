using System.Windows.Controls;
using System.Windows.Input;

namespace ProxiFyre;

public partial class LogsTab : UserControl
{
    public LogsTab()
    {
        InitializeComponent();
    }

    public ListBox Logs => LogList;

    public void ScrollToEnd()
    {
        LogList.ScrollIntoView(LogList.Items.Count > 0 ? LogList.Items[LogList.Items.Count - 1] : null);
    }

    private void LogList_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.C && Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
        {
            CopySelectedLines();
            e.Handled = true;
        }
    }

    private void CopySelectedMenuItem_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        CopySelectedLines();
    }

    private void CopyAllMenuItem_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        CopyItems(LogList.Items.Cast<object>());
    }

    private void CopySelectedLines()
    {
        var selectedItems = LogList.SelectedItems.Cast<object>().ToArray();
        CopyItems(selectedItems.Length > 0 ? selectedItems : LogList.Items.Cast<object>());
    }

    private static void CopyItems(IEnumerable<object> items)
    {
        var text = string.Join(Environment.NewLine, items.Select(item => item?.ToString()).Where(line => !string.IsNullOrEmpty(line)));
        if (!string.IsNullOrEmpty(text))
        {
            System.Windows.Clipboard.SetText(text);
        }
    }
}
