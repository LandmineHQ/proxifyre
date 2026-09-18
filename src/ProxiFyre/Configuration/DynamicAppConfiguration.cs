namespace ProxiFyre;

internal sealed class DynamicAppConfiguration
{
    private AppConfiguration _current;
    private long _generation;

    public DynamicAppConfiguration(AppConfiguration initialConfiguration)
    {
        _current = initialConfiguration;
    }

    public AppConfiguration Current => Volatile.Read(ref _current);

    public long Generation => Volatile.Read(ref _generation);

    public void Update(AppConfiguration configuration)
    {
        Volatile.Write(ref _current, configuration);
        Interlocked.Increment(ref _generation);
    }
}
