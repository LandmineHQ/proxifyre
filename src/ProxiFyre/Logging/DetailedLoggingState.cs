namespace ProxiFyre;

internal sealed class DetailedLoggingState
{
    private int _enabled;

    public DetailedLoggingState(bool enabled)
    {
        _enabled = enabled ? 1 : 0;
    }

    public bool Enabled => Volatile.Read(ref _enabled) != 0;

    public void Update(bool enabled)
    {
        Volatile.Write(ref _enabled, enabled ? 1 : 0);
    }
}
