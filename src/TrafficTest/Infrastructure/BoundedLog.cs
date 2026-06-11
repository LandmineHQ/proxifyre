namespace TrafficTest;

internal sealed class BoundedLog
{
    private readonly int _capacity;
    private readonly Queue<string> _lines = new();
    private readonly object _sync = new();

    public BoundedLog(int capacity)
    {
        _capacity = capacity;
    }

    public void Add(string line)
    {
        lock (_sync)
        {
            _lines.Enqueue(line);
            while (_lines.Count > _capacity)
            {
                _lines.Dequeue();
            }
        }
    }

    public string[] Snapshot()
    {
        lock (_sync)
        {
            return _lines.ToArray();
        }
    }
}
