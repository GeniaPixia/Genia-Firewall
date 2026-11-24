namespace GeniaFirewall.Intelligence;

/// <summary>Display-only filters for an in-memory snapshot; no firewall changes.</summary>
public enum InsightViewFilter
{
    All,
    ExternalTcp,
    Loopback,
    LanTcp,
    Listeners,
    UdpSockets,
    Unknown
}

public static class NetworkInsightFiltering
{
    public static bool Matches(NetworkObservation row, InsightViewFilter filter, string? query,
        string? pairedProcessName = null)
    {
        ArgumentNullException.ThrowIfNull(row);
        var matchesScope = filter switch
        {
            InsightViewFilter.ExternalTcp => row.Scope == ObservationScope.ExternalCandidate,
            InsightViewFilter.Loopback => row.Scope == ObservationScope.Loopback,
            InsightViewFilter.LanTcp => row.Scope == ObservationScope.PrivateOrLan,
            InsightViewFilter.Listeners => row.Scope == ObservationScope.Listener,
            InsightViewFilter.UdpSockets => row.Scope == ObservationScope.LocalUdpSocket,
            InsightViewFilter.Unknown => row.Scope == ObservationScope.Unknown,
            _ => true
        };
        if (!matchesScope) return false;
        if (string.IsNullOrWhiteSpace(query)) return true;
        var v = query.Trim();
        return row.Pid.ToString().Contains(v, StringComparison.OrdinalIgnoreCase)
            || row.ProcessName.Contains(v, StringComparison.OrdinalIgnoreCase)
            || row.ExecutablePath.Contains(v, StringComparison.OrdinalIgnoreCase)
            || row.Protocol.Contains(v, StringComparison.OrdinalIgnoreCase)
            || row.LocalEndpoint.Contains(v, StringComparison.OrdinalIgnoreCase)
            || row.RemoteEndpoint.Contains(v, StringComparison.OrdinalIgnoreCase)
            || pairedProcessName?.Contains(v, StringComparison.OrdinalIgnoreCase) == true;
    }
}
