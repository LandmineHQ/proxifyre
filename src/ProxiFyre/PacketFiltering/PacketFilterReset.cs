namespace ProxiFyre;

internal static class PacketFilterReset
{
    public static void Reset(Action<string> log)
    {
        var handle = NdisApi.OpenFilterDriver("NDISRD");
        if (handle == IntPtr.Zero)
        {
            var error = NdisApi.LastWin32Error;
            throw new InvalidOperationException($"Failed to open WinpkFilter driver NDISRD. Win32 error {error}: {new System.ComponentModel.Win32Exception(error).Message}");
        }

        try
        {
            var adapterList = new NdisApi.TcpAdapterList();
            if (!NdisApi.GetTcpipBoundAdaptersInfo(handle, ref adapterList))
            {
                throw new InvalidOperationException("Failed to enumerate TCP/IP bound adapters.");
            }

            NdisApi.ResetPacketFilterTable(handle);

            var resetCount = 0;
            for (var i = 0; i < adapterList.Count; i++)
            {
                var adapter = adapterList.GetHandle(i);
                if (adapter == IntPtr.Zero)
                {
                    continue;
                }

                NdisApi.SetPacketEvent(handle, adapter, IntPtr.Zero);
                var mode = new NdisApi.AdapterMode
                {
                    AdapterHandle = adapter,
                    Flags = 0
                };

                NdisApi.SetAdapterMode(handle, ref mode);
                NdisApi.FlushAdapterPacketQueue(handle, adapter);
                resetCount++;
            }

            log($"Reset WinpkFilter mode for {resetCount} adapter(s).");
        }
        finally
        {
            NdisApi.CloseFilterDriver(handle);
        }
    }
}
