namespace GeniaFirewall.Intelligence;

/// <summary>
/// A purely observational, same-snapshot match between the two rows of a
/// localhost TCP connection. A match is a hint, not proof of a network route
/// or process identity. Never merges, removes or rewrites original rows.
/// </summary>
public static class LoopbackPeerCorrelation
{
    public static IReadOnlyDictionary<NetworkObservation, NetworkObservation> FindPeers(
        IReadOnlyList<NetworkObservation> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);

        // Only exact reverse endpoint pairs are accepted. Mixed TCP4/TCP6,
        // UDP, listeners and incomplete states cannot produce matches.
        var eligible = rows.Where(CanMatch).ToArray();
        var byDirection = eligible
            .GroupBy(row => new DirectionKey(row.Protocol, row.LocalEndpoint, row.RemoteEndpoint))
            .ToDictionary(group => group.Key, group => group.ToArray());

        var result = new Dictionary<NetworkObservation, NetworkObservation>();
        foreach (var row in eligible)
        {
            var forward = new DirectionKey(row.Protocol, row.LocalEndpoint, row.RemoteEndpoint);
            var reverse = new DirectionKey(row.Protocol, row.RemoteEndpoint, row.LocalEndpoint);
            if (!byDirection.TryGetValue(forward, out var candidates) || candidates.Length != 1)
                continue;
            if (!byDirection.TryGetValue(reverse, out var partners) || partners.Length != 1)
                continue;

            var partner = partners[0];
            // A same-process row can represent the process connecting to itself;
            // don't label it as a peer process in this preview.
            if (partner.Pid == row.Pid || ReferenceEquals(partner, row))
                continue;
            result[row] = partner;
        }
        return result;
    }

    private static bool CanMatch(NetworkObservation row) =>
        row.Scope == ObservationScope.Loopback
        && (row.Protocol == "TCP" || row.Protocol == "TCP6")
        && string.Equals(row.State, "ESTABLISHED", StringComparison.Ordinal)
        && row.LocalEndpoint.Length > 0
        && row.RemoteEndpoint.Length > 0
        && row.RemoteEndpoint != "—";

    private readonly record struct DirectionKey(
        string Protocol, string LocalEndpoint, string RemoteEndpoint);
}
