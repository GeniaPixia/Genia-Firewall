using System.Net;
using System.Net.Sockets;

namespace GeniaFirewall.Intelligence;

/// <summary>
/// Approximate address scope, not proof of Internet reachability, tracking or maliciousness.
/// Adapted conceptually from the locally supplied GeniaVizor 0.5.0 Preview 5
/// PrivacyInspector / TrafficInspector; independent GeniaFirewall implementation.
/// </summary>
public enum ObservationScope
{
    ExternalCandidate,
    Loopback,
    PrivateOrLan,
    LocalUdpSocket,
    Listener,
    Unknown
}

public static class EndpointScope
{
    public static ObservationScope ClassifyTcpRemote(string? address)
    {
        if (string.IsNullOrWhiteSpace(address) ||
            !IPAddress.TryParse(address, out var ip))
            return ObservationScope.Unknown;

        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();

        if (IPAddress.IsLoopback(ip))
            return ObservationScope.Loopback;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 10 ||
                b[0] == 172 && b[1] >= 16 && b[1] <= 31 ||
                b[0] == 192 && b[1] == 168 ||
                b[0] == 169 && b[1] == 254 ||
                b[0] == 100 && b[1] >= 64 && b[1] <= 127)
                return ObservationScope.PrivateOrLan;

            // Reject documentation, benchmarking, special-use and multicast ranges.
            if (b[0] is 0 or 127 || b[0] >= 224 ||
                b[0] == 192 && (b[1] == 0 || b[1] == 88 && b[2] == 99) ||
                b[0] == 192 && b[1] == 0 && b[2] == 2 ||
                b[0] == 198 && (b[1] is 18 or 19 ||
                    b[1] == 51 && b[2] == 100) ||
                b[0] == 203 && b[1] == 0 && b[2] == 113)
                return ObservationScope.Unknown;

            return ObservationScope.ExternalCandidate;
        }

        if (ip.AddressFamily != AddressFamily.InterNetworkV6)
            return ObservationScope.Unknown;

        var raw = ip.GetAddressBytes();
        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (raw[0] & 0xfe) == 0xfc)
            return ObservationScope.PrivateOrLan;

        // Global-unicast candidate 2000::/3, except documentation 2001:db8::/32.
        if ((raw[0] & 0xe0) != 0x20 ||
            raw[0] == 0x20 && raw[1] == 0x01 &&
            raw[2] == 0x0d && raw[3] == 0xb8)
            return ObservationScope.Unknown;
        return ObservationScope.ExternalCandidate;
    }
}
