namespace ProxiFyre;

internal sealed class DynamicAppConfiguration
{
    private AppConfiguration _current;

    public DynamicAppConfiguration(AppConfiguration initialConfiguration)
    {
        _current = initialConfiguration;
    }

    public AppConfiguration Current => Volatile.Read(ref _current);

    public void Update(AppConfiguration configuration)
    {
        Volatile.Write(ref _current, configuration);
    }
}
