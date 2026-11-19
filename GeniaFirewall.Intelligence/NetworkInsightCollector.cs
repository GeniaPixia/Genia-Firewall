using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace GeniaFirewall.Intelligence;

/// <summary>
/// On-demand Win32 owner-table snapshot. No services, DNS, packet capture, hooks,
/// firewall mutations, process injection, file writes, or external calls.
/// UDP tables expose only local sockets: never assign an observed remote UDP host.
/// </summary>
public sealed class NetworkInsightCollector
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpOwnerPidAll = 5;
    private const int UdpOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;
    private const int MaxTableBytes = 16 * 1024 * 1024;
    private const int MaxRowsPerTable = 100_000;
    private const int MaxVisibleObservations = 2_000;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    public NetworkInsightSnapshot Collect()
    {
        if (!OperatingSystem.IsWindows())
            return new NetworkInsightSnapshot([], false, false,
                ["Windows networking APIs are unavailable."], DateTimeOffset.Now);

        var observations = new List<RawConnection>(512);
        var issues = new List<string>();
        ReadTable(true, false, observations, issues);
        ReadTable(true, true, observations, issues);
        ReadTable(false, false, observations, issues);
        ReadTable(false, true, observations, issues);

        var seen = new HashSet<RawConnection>();
        var names = new Dictionary<int, (string Name, string Path)>();
        var rows = new List<NetworkObservation>();
        var truncated = false;
        foreach (var row in observations)
        {
            if (row.Pid <= 0 || !seen.Add(row)) continue;
            if (rows.Count == MaxVisibleObservations)
            {
                truncated = true;
                break;
            }

            if (!names.TryGetValue(row.Pid, out var identity))
            {
                var path = TryGetImagePath(row.Pid);
                // Protected processes may deny image path access. A name-only
                // fallback is useful but does not establish executable identity.
                identity = (string.IsNullOrEmpty(path) ? TryGetProcessName(row.Pid) :
                    Path.GetFileName(path), path ?? string.Empty);
                names[row.Pid] = identity;
            }

            var scope = row.Protocol.StartsWith("UDP", StringComparison.Ordinal)
                ? ObservationScope.LocalUdpSocket
                : row.State == "LISTEN"
                    ? ObservationScope.Listener
                    : EndpointScope.ClassifyTcpRemote(row.RemoteAddress);

            rows.Add(new NetworkObservation(
                row.Pid, identity.Name, identity.Path, row.Protocol,
                FormatEndpoint(row.LocalAddress, row.LocalPort),
                row.RemotePort == 0 ? "—" : FormatEndpoint(row.RemoteAddress, row.RemotePort),
                row.State, scope));
        }

        return new NetworkInsightSnapshot(
            rows.OrderBy(r => r.Scope)
                .ThenBy(r => r.ProcessName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(r => r.Pid).ToArray(),
            issues.Count == 0, truncated, issues, DateTimeOffset.Now);
    }

    private static string FormatEndpoint(string ip, int port) =>
        ip.Contains(':') ? $"[{ip}]:{port}" : $"{ip}:{port}";

    private static void ReadTable(
        bool tcp, bool ipv6, List<RawConnection> sink, List<string> issues)
    {
        var family = ipv6 ? AfInet6 : AfInet;
        var tableLabel = (tcp ? "TCP" : "UDP") + (ipv6 ? "6" : "4");
        var bytes = ReadNativeTable(tcp, family, out var error);
        if (bytes is null)
        {
            issues.Add($"{tableLabel} unavailable (Win32 {error})");
            return;
        }

        var rowSize = tcp ? (ipv6 ? 56 : 24) : (ipv6 ? 28 : 12);
        var count = BitConverter.ToInt32(bytes, 0);
        if (count < 0 || count > MaxRowsPerTable ||
            (long)count * rowSize + 4 > bytes.Length)
        {
            issues.Add($"{tableLabel} returned an invalid table size");
            return;
        }

        for (var i = 0; i < count; ++i)
        {
            var offset = 4 + i * rowSize;
            if (tcp)
            {
                var state = BitConverter.ToInt32(bytes, offset + (ipv6 ? 48 : 0));
                // Only active or listening TCP rows; other states are not destination evidence.
                if (state is not (2 or 3 or 4 or 5)) continue;

                var local = ipv6 ? Ip6(bytes, offset) : Ip4(bytes, offset + 4);
                var remote = ipv6 ? Ip6(bytes, offset + 24) : Ip4(bytes, offset + 12);
                var localPort = Port(bytes, offset + (ipv6 ? 20 : 8));
                var remotePort = Port(bytes, offset + (ipv6 ? 44 : 16));
                var pid = BitConverter.ToInt32(bytes, offset + (ipv6 ? 52 : 20));
                if (state != 2 && remotePort <= 0) continue;

                sink.Add(new RawConnection(pid, ipv6 ? "TCP6" : "TCP",
                    local, localPort, remote, state == 2 ? 0 : remotePort,
                    state == 2 ? "LISTEN" : state == 5 ? "ESTABLISHED" :
                    state == 3 ? "SYN_SENT" : "SYN_RECV"));
            }
            else
            {
                // UDP owner tables describe local sockets, not destinations.
                var local = ipv6 ? Ip6(bytes, offset) : Ip4(bytes, offset);
                var localPort = Port(bytes, offset + (ipv6 ? 20 : 4));
                var pid = BitConverter.ToInt32(bytes, offset + (ipv6 ? 24 : 8));
                sink.Add(new RawConnection(pid, ipv6 ? "UDP6" : "UDP",
                    local, localPort, string.Empty, 0, "SOCKET"));
            }
        }
    }

    private static string Ip4(byte[] b, int offset) =>
        new IPAddress(b.AsSpan(offset, 4)).ToString();

    private static string Ip6(byte[] b, int offset) =>
        new IPAddress(b.AsSpan(offset, 16)).ToString();

    // Ports in owner tables are network-order bytes stored in DWORDs.
    private static int Port(byte[] bytes, int index) =>
        (bytes[index] << 8) | bytes[index + 1];

    private static byte[]? ReadNativeTable(bool tcp, int family, out uint code)
    {
        code = 0;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var size = 0;
            code = tcp
                ? GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TcpOwnerPidAll, 0)
                : GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, UdpOwnerPid, 0);
            if (code != ErrorInsufficientBuffer ||
                size < 4 || size > MaxTableBytes) return null;

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                code = tcp
                    ? GetExtendedTcpTable(buffer, ref size, false, family, TcpOwnerPidAll, 0)
                    : GetExtendedUdpTable(buffer, ref size, false, family, UdpOwnerPid, 0);
                if (code == ErrorInsufficientBuffer) continue;
                if (code != 0 || size < 4 || size > MaxTableBytes) return null;
                var data = new byte[size];
                Marshal.Copy(buffer, data, 0, size);
                return data;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return null;
    }

    private static string TryGetProcessName(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            var name = process.ProcessName;
            // ProcessName is not a verified EXE path or filename.
            // Do not manufacture an ".exe" suffix (PID 4 is "System").
            return ProcessIdentityLabel.NameOnlyOrPid(pid, name);
        }
        catch (ArgumentException) { } // process exited
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { } // access denied
        catch (System.Security.SecurityException) { }

        return ProcessIdentityLabel.NameOnlyOrPid(pid, null);
    }

    private static string? TryGetImagePath(int pid)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var builder = new StringBuilder(32768);
            var length = builder.Capacity;
            return QueryFullProcessImageName(handle, 0, builder, ref length)
                ? builder.ToString() : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool sort, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool sort, int family, int tableClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process, uint flags, StringBuilder name, ref int length);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private sealed record RawConnection(int Pid, string Protocol,
        string LocalAddress, int LocalPort, string RemoteAddress,
        int RemotePort, string State);
}

public sealed record NetworkObservation(
    int Pid, string ProcessName, string ExecutablePath,
    string Protocol, string LocalEndpoint, string RemoteEndpoint,
    string State, ObservationScope Scope);

public sealed record NetworkInsightSnapshot(
    IReadOnlyList<NetworkObservation> Connections, bool Complete, bool Truncated,
    IReadOnlyList<string> Issues, DateTimeOffset CapturedAt);
