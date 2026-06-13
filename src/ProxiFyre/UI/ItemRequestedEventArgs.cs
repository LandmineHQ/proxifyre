namespace ProxiFyre;

public sealed class ItemRequestedEventArgs(object? item) : EventArgs
{
    public object? Item { get; } = item;
}
