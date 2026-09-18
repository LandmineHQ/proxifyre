namespace ProxiFyre;

public sealed class UuPatchToggleRequestedEventArgs(bool enabled) : EventArgs
{
    public bool Enabled { get; } = enabled;
}
