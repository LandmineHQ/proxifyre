namespace ProxiFyre;

internal unsafe interface IAdapterPacketProcessor
{
    void ProcessPacket(NdisApi.IntermediateBuffer* buffer);
}

internal sealed unsafe class AdapterPipeline
{
    private readonly IntPtr _driverHandle;

    public AdapterPipeline(
        IntPtr driverHandle,
        IntPtr handle,
        string name,
        int mtu,
        int interfaceIndex)
    {
        _driverHandle = driverHandle;
        Handle = handle;
        Name = name;
        Mtu = mtu;
        InterfaceIndex = interfaceIndex;
    }

    public IntPtr Handle { get; }

    public string Name { get; }

    public int Mtu { get; }

    public int InterfaceIndex { get; }

    public long PacketsRead { get; private set; }

    public bool TryReadAndProcess(IAdapterPacketProcessor processor)
    {
        var buffer = default(NdisApi.IntermediateBuffer);
        var request = new NdisApi.EthRequest
        {
            AdapterHandle = Handle,
            Buffer = (IntPtr)(&buffer)
        };

        if (!NdisApi.ReadPacket(_driverHandle, ref request))
        {
            return false;
        }

        buffer.AdapterOrListFlink = Handle;
        PacketsRead++;
        processor.ProcessPacket(&buffer);
        return true;
    }
}
