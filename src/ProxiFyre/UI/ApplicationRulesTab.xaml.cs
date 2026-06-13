using System.Windows;
using System.Windows.Controls;

namespace ProxiFyre;

public partial class ApplicationRulesTab : UserControl
{
    public ApplicationRulesTab()
    {
        InitializeComponent();
    }

    public event EventHandler? SearchChanged;

    public event EventHandler<ItemRequestedEventArgs>? EditAppRequested;

    public event EventHandler<ItemRequestedEventArgs>? RemoveAppRequested;

    public ListBox Apps => AppsList;

    public string SearchText => SearchBox.Text;

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        SearchChanged?.Invoke(this, EventArgs.Empty);
    }

    private void EditAppButton_Click(object sender, RoutedEventArgs e)
    {
        EditAppRequested?.Invoke(this, new ItemRequestedEventArgs((sender as FrameworkElement)?.DataContext));
    }

    private void RemoveAppButton_Click(object sender, RoutedEventArgs e)
    {
        RemoveAppRequested?.Invoke(this, new ItemRequestedEventArgs((sender as FrameworkElement)?.DataContext));
    }
}
