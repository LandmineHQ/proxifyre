namespace ProxiFyre;

public sealed class TextRequestedEventArgs(string text) : EventArgs
{
    public string Text { get; } = text;
}
