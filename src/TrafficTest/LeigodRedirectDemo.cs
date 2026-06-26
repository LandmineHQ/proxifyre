using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace TrafficTest;

internal static class LeigodRedirectDemo
{
    public static async Task<int> RunAsync(string[] args)
    {
        Console.WriteLine("=== Leigod WFP Redirection Demo (Parent) ===");
        
        string targetUrl = "https://store.steampowered.com/";
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals("--url", StringComparison.OrdinalIgnoreCase))
            {
                targetUrl = args[i + 1];
                break;
            }
        }

        Console.WriteLine($"Target Test URL: {targetUrl}");

        var currentExe = Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrEmpty(currentExe) || !File.Exists(currentExe))
        {
            Console.Error.WriteLine("Failed to locate current executable path.");
            return 1;
        }

        var tempDir = Path.Combine(Path.GetTempPath(), "LeigodRedirectDemo_" + Path.GetRandomFileName());
        var targetExe = Path.Combine(tempDir, "steamwebhelper.exe");

        var sourceDir = Path.GetDirectoryName(currentExe);
        if (string.IsNullOrEmpty(sourceDir))
        {
            Console.Error.WriteLine("Failed to resolve source directory.");
            return 1;
        }

        var parentDir = Path.GetDirectoryName(sourceDir);
        if (string.IsNullOrEmpty(parentDir))
        {
            Console.Error.WriteLine("Failed to resolve parent directory.");
            return 1;
        }
        var rootBin = Path.GetDirectoryName(parentDir);
        if (string.IsNullOrEmpty(rootBin))
        {
            Console.Error.WriteLine("Failed to resolve root bin directory.");
            return 1;
        }
        var moniker = Path.GetFileName(sourceDir);
        var proxifyreExe = Path.GetFullPath(Path.Combine(rootBin, "ProxiFyre", moniker, "ProxiFyre.exe"));

        if (!File.Exists(proxifyreExe))
        {
            Console.Error.WriteLine($"Failed to locate ProxiFyre executable at: {proxifyreExe}");
            return 1;
        }

        Process? proxifyreProcess = null;
        try
        {
            Directory.CreateDirectory(tempDir);
            foreach (var file in Directory.EnumerateFiles(sourceDir))
            {
                var fileName = Path.GetFileName(file);
                File.Copy(file, Path.Combine(tempDir, fileName), overwrite: true);
            }
            File.Copy(currentExe, targetExe, overwrite: true);
            Console.WriteLine($"Copied test executable and dependencies to: {tempDir}");

            // Create temp config for the background ProxiFyre run
            var tempConfigPath = Path.Combine(tempDir, "app-config.json");
            var configContent = System.Text.Json.JsonSerializer.Serialize(new
            {
                coreProcessName = "steamwebhelper.exe",
                enableFakeIpWhitelist = true,
                apps = new[] { "steamwebhelper.exe" }
            }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(tempConfigPath, configContent);

            // Start ProxiFyre in the background
            Console.WriteLine($"Starting background ProxiFyre from: {proxifyreExe}");
            var proxifyreStartInfo = new ProcessStartInfo
            {
                FileName = proxifyreExe,
                Arguments = $"--run --config \"{tempConfigPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            proxifyreProcess = Process.Start(proxifyreStartInfo);
            if (proxifyreProcess == null)
            {
                Console.Error.WriteLine("Failed to start background ProxiFyre process.");
                return 1;
            }

            // Wait a moment for ProxiFyre to initialize the NDIS filter table
            await Task.Delay(1500);

            // Flush DNS cache to ensure Windows DNS Client queries the network instead of using cached results
            try
            {
                using var flushProc = Process.Start(new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true
                });
                if (flushProc != null)
                {
                    await flushProc.WaitForExitAsync();
                    Console.WriteLine("Flushed Windows DNS cache.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to flush DNS cache: {ex.Message}");
            }

            Console.WriteLine("Parent: Sending test DNS query to port 53 to check redirection and whitelist...");
            try
            {
                var parentSpoofedIp = await SendDnsQueryCustomPortAsync("fakeip-20-205-243-166.store.steampowered.com", "8.8.8.8", 53, TimeSpan.FromSeconds(3));
                if (parentSpoofedIp != null)
                {
                    Console.WriteLine($"Parent: DNS query completed successfully. IP = {parentSpoofedIp}");
                }
                else
                {
                    Console.WriteLine("Parent Warning: DNS query to port 53 returned null (possible Leigod redirection/hijack)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Parent Warning: DNS query to port 53 failed: {ex.Message}");
            }

            Console.WriteLine("Starting child steamwebhelper.exe...");
            var startInfo = new ProcessStartInfo
            {
                FileName = targetExe,
                Arguments = $"run-leigod-demo --url \"{targetUrl}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var child = Process.Start(startInfo);
            if (child == null)
            {
                Console.Error.WriteLine("Failed to start child process.");
                return 1;
            }

            Console.WriteLine($"Child process started. PID={child.Id}");

            // Monitor connections for the child process
            Console.WriteLine("Monitoring child TCP connections for WFP redirection...");
            bool redirectionCaptured = false;
            for (int i = 0; i < 80; i++)
            {
                await Task.Delay(250);
                if (child.HasExited) break;

                var tcpRows = WindowsNetworkTable.GetTcpRowsForProcesses(new[] { child.Id }.ToHashSet());
                foreach (var row in tcpRows.Where(r => r.State != TcpState.Listen))
                {
                    Console.WriteLine($"[OS TCP Table] PID={row.ProcessId} Local={row.LocalEndPoint} -> Remote={row.RemoteEndPoint} State={row.State}");
                    if (row.RemoteAddress == "127.0.0.1" || row.RemoteAddress == "::1" || row.RemotePort == 12657 || row.RemotePort == 12658)
                    {
                        redirectionCaptured = true;
                    }
                }
            }

            // Wait for child exit
            await child.WaitForExitAsync();
            var stdout = await child.StandardOutput.ReadToEndAsync();
            var stderr = await child.StandardError.ReadToEndAsync();

            Console.WriteLine("\n=== Child Process Output ===");
            Console.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                Console.WriteLine("Errors:\n" + stderr);
            }
            Console.WriteLine("============================");

            if (redirectionCaptured)
            {
                Console.WriteLine("\n[SUCCESS] WFP Redirection captured! Traffic was successfully redirected to Leigod.");
                return 0;
            }
            else
            {
                Console.WriteLine("\n[FAILED] WFP Redirection was not captured. Is Leigod running and configured to accelerate Steam?");
                return 1;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error during demo: {ex.Message}");
            return 1;
        }
        finally
        {
            if (proxifyreProcess is { HasExited: false })
            {
                Console.WriteLine("Stopping background ProxiFyre process...");
                proxifyreProcess.Kill(entireProcessTree: true);
                try
                {
                    await proxifyreProcess.WaitForExitAsync();
                }
                catch { }
                proxifyreProcess.Dispose();
            }

            try
            {
                if (Directory.Exists(tempDir))
                {
                    Directory.Delete(tempDir, recursive: true);
                }
            }
            catch { }
        }
    }

    public static async Task<int> RunChildAsync(string[] args)
    {
        // Child execution mode
        try
        {
            string targetUrl = "https://store.steampowered.com/";
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i].Equals("--url", StringComparison.OrdinalIgnoreCase))
                {
                    targetUrl = args[i + 1];
                    break;
                }
            }

            string host = "store.steampowered.com";
            int port = 443;
            try
            {
                var uriString = targetUrl;
                if (!uriString.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                    !uriString.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    uriString = "https://" + uriString;
                }
                var uri = new Uri(uriString);
                host = uri.Host;
                port = uri.Port;
            }
            catch
            {
                host = targetUrl;
            }

            IPAddress targetIp;
            try
            {
                Console.WriteLine($"Child: Resolving {host}...");
                var ips = await Dns.GetHostAddressesAsync(host);
                targetIp = ips[0];
            }
            catch (Exception ex)
            {
                if (host.Contains("steam", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"Child: DNS failed for {host}: {ex.Message}. Using hardcoded fallback Steam IP.");
                    targetIp = IPAddress.Parse("23.15.141.198"); // A standard Akamai Steam CDN IP
                }
                else
                {
                    Console.WriteLine($"Child Error: DNS resolution failed for {host}: {ex.Message}");
                    return 1;
                }
            }
            Console.WriteLine($"Child: Target host={host}, IP={targetIp}");

            if (!host.Contains("steam", StringComparison.OrdinalIgnoreCase))
            {
                string fakeHost = $"fakeip-{targetIp.ToString().Replace('.', '-')}.store.steampowered.com";
                Console.WriteLine($"Child: Triggering Fake IP whitelist injection via custom port DNS query for: {fakeHost}");
                try
                {
                    var spoofedIp = await SendDnsQueryCustomPortAsync(fakeHost, "8.8.8.8", 5353, TimeSpan.FromSeconds(3));
                    if (spoofedIp != null)
                    {
                        Console.WriteLine($"Child: Fake IP DNS resolution completed. Resolved IP: {spoofedIp}");
                    }
                    else
                    {
                        Console.WriteLine("Child Warning: Fake IP DNS query returned null IP");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Child Warning: Fake IP DNS query failed: {ex.Message}");
                }
            }

            Console.WriteLine($"Child: Connecting to {host}:{port}...");
            using var client = new TcpClient();
            await client.ConnectAsync(targetIp, port);

            if (client.Connected)
            {
                Console.WriteLine($"Child: TCP connection established successfully.");
                Console.WriteLine($"Child: Socket thinks RemoteEndPoint is: {client.Client.RemoteEndPoint}");

                // Perform TLS Handshake to verify certificate
                using var sslStream = new SslStream(client.GetStream(), false, (sender, cert, chain, errors) => {
                    if (cert != null)
                    {
                        Console.WriteLine($"Child TLS Handshake Subject: {cert.Subject}");
                        Console.WriteLine($"Child TLS Handshake Issuer: {cert.Issuer}");
                    }
                    return true; // Accept any certificate for the demo
                });

                Console.WriteLine("Child: Initiating SSL/TLS handshake...");
                await sslStream.AuthenticateAsClientAsync(host);
                Console.WriteLine("Child: SSL/TLS handshake completed successfully.");
                
                Console.WriteLine("Child: Holding connection open for 5 seconds for parent monitoring...");
                await Task.Delay(5000);

                sslStream.Close();
                client.Close();
                return 0;
            }
            else
            {
                Console.WriteLine("Child Error: Connection failed.");
                return 1;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Child Exception: {ex.Message}");
            return 1;
        }
    }

    private static async Task<IPAddress?> SendDnsQueryCustomPortAsync(string domain, string dnsServer, int port, TimeSpan timeout)
    {
        try
        {
            ushort transactionId = (ushort)Random.Shared.Next(1, 65535);
            var payload = new List<byte>();
            
            // Header
            payload.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)transactionId)));
            payload.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)0x0100))); // Standard query, recursion desired
            payload.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)1)));      // 1 Question
            payload.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)0)));
            payload.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)0)));
            payload.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)0)));
            
            // Question: QNAME
            var labels = domain.Split('.');
            foreach (var label in labels)
            {
                var bytes = System.Text.Encoding.ASCII.GetBytes(label);
                payload.Add((byte)bytes.Length);
                payload.AddRange(bytes);
            }
            payload.Add(0); // QNAME terminator
            
            // QTYPE: A (1)
            payload.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)1)));
            // QCLASS: IN (1)
            payload.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)1)));

            using var udpClient = new UdpClient();
            var serverEndPoint = new IPEndPoint(IPAddress.Parse(dnsServer), port);
            byte[] queryBytes = payload.ToArray();
            
            await udpClient.SendAsync(queryBytes, queryBytes.Length, serverEndPoint);
            
            var receiveTask = udpClient.ReceiveAsync();
            var delayTask = Task.Delay(timeout);
            var completedTask = await Task.WhenAny(receiveTask, delayTask);
            
            if (completedTask == delayTask)
            {
                throw new TimeoutException("DNS query timed out");
            }
            
            var result = await receiveTask;
            byte[] responseBytes = result.Buffer;
            if (responseBytes.Length < 12) return null;
            
            ushort resTxId = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(responseBytes.AsSpan(0, 2));
            if (resTxId != transactionId) return null;
            
            // Parse QNAME to skip it
            int offset = 12;
            while (offset < responseBytes.Length)
            {
                byte len = responseBytes[offset];
                if (len == 0) { offset++; break; }
                if ((len & 0xC0) == 0xC0) { offset += 2; break; }
                offset += 1 + len;
            }
            offset += 4; // Skip QTYPE and QCLASS
            
            // Answer section parsing
            if (offset + 12 <= responseBytes.Length)
            {
                if ((responseBytes[offset] & 0xC0) == 0xC0) offset += 2;
                else
                {
                    while (offset < responseBytes.Length)
                    {
                        byte len = responseBytes[offset];
                        if (len == 0) { offset++; break; }
                        offset += 1 + len;
                    }
                }
                
                ushort type = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(responseBytes.AsSpan(offset, 2));
                ushort rdLen = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(responseBytes.AsSpan(offset + 8, 2));
                offset += 10;
                
                if (type == 1 && rdLen == 4 && offset + 4 <= responseBytes.Length)
                {
                    byte[] ipBytes = new byte[4];
                    Array.Copy(responseBytes, offset, ipBytes, 0, 4);
                    return new IPAddress(ipBytes);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Custom DNS Query Error: {ex.Message}");
        }
        return null;
    }
}
