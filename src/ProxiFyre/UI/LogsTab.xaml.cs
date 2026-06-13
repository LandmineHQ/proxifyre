using System.Windows.Controls;

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
}
