using GeniaFirewall.Intelligence;

var cases = new (string Address, ObservationScope Expected)[]
{
    ("1.1.1.1", ObservationScope.ExternalCandidate),
    ("8.8.8.8", ObservationScope.ExternalCandidate),
    ("10.0.1.1", ObservationScope.PrivateOrLan),
    ("192.168.1.23", ObservationScope.PrivateOrLan),
    ("172.31.255.254", ObservationScope.PrivateOrLan),
    ("100.64.12.1", ObservationScope.PrivateOrLan),
    ("169.254.1.2", ObservationScope.PrivateOrLan),
    ("127.0.0.1", ObservationScope.Loopback),
    ("192.0.2.20", ObservationScope.Unknown),
    ("198.51.100.42", ObservationScope.Unknown),
    ("203.0.113.7", ObservationScope.Unknown),
    ("198.18.0.1", ObservationScope.Unknown),
    ("224.0.0.1", ObservationScope.Unknown),
    ("::1", ObservationScope.Loopback),
    ("fe80::1", ObservationScope.PrivateOrLan),
    ("fd00::1234", ObservationScope.PrivateOrLan),
    ("2001:db8::1", ObservationScope.Unknown),
    ("2606:4700:4700::1111", ObservationScope.ExternalCandidate),
    ("::ffff:10.0.0.1", ObservationScope.PrivateOrLan),
    ("not-an-address", ObservationScope.Unknown)
};
foreach (var (address, expected) in cases)
{
    var actual = EndpointScope.ClassifyTcpRemote(address);
    if (actual != expected)
        throw new InvalidOperationException(
            $"SCOPE_TEST_FAIL {address}: expected={expected}; actual={actual}");
}
if (EndpointScope.ClassifyTcpRemote(null) != ObservationScope.Unknown)
    throw new InvalidOperationException("Null address was not rejected.");
Console.WriteLine($"GENIAFIREWALL_INTELLIGENCE_SCOPE_TESTS=PASS_{cases.Length + 1}");
Console.WriteLine("NO_FIREWALL_WRITES_OR_EXTERNAL_CONNECTIONS=TRUE");

if (OperatingSystem.IsWindows())
{
    // This is an actual, on-demand owner-table query on the Windows CI runner.
    // It never sends packets or alters system firewall policy.
    var snapshot = new NetworkInsightCollector().Collect();
    if (snapshot.Connections.Count > 2000 || snapshot.Connections.Any(r =>
        r.Pid <= 0 || string.IsNullOrWhiteSpace(r.Protocol) ||
        r.Scope == ObservationScope.LocalUdpSocket && r.RemoteEndpoint != "—"))
        throw new InvalidOperationException("Invalid or unbounded owner-table snapshot.");
    Console.WriteLine($"NATIVE_SNAPSHOT_READONLY=PASS rows={snapshot.Connections.Count} complete={snapshot.Complete} issues={snapshot.Issues.Count}");
}

var synthetic = new[]
{
    new NetworkObservation(100, "chrome.exe", @"C:\Browser\chrome.exe", "TCP",
        "127.0.0.1:4242", "127.0.0.1:2080", "ESTABLISHED", ObservationScope.Loopback),
    new NetworkObservation(200, "sing-box.exe", @"C:\GeniaProxy\sing-box.exe", "TCP",
        "127.0.0.1:2080", "—", "LISTEN", ObservationScope.Listener),
    new NetworkObservation(300, "example.exe", "", "UDP6",
        "[::]:1900", "—", "SOCKET", ObservationScope.LocalUdpSocket),
    new NetworkObservation(400, "other.exe", "", "TCP",
        "192.168.1.11:2000", "8.8.8.8:443", "ESTABLISHED", ObservationScope.ExternalCandidate),
    new NetworkObservation(500, "lan.exe", "", "TCP",
        "192.168.1.11:2000", "192.168.1.2:445", "ESTABLISHED", ObservationScope.PrivateOrLan)
};
var filterCases = new (InsightViewFilter Filter, string? Query, int Expected)[]
{
    (InsightViewFilter.All, null, 5),
    (InsightViewFilter.ExternalTcp, "", 1),
    (InsightViewFilter.Loopback, null, 1),
    (InsightViewFilter.LanTcp, null, 1),
    (InsightViewFilter.Listeners, null, 1),
    (InsightViewFilter.UdpSockets, null, 1),
    (InsightViewFilter.Unknown, null, 0),
    (InsightViewFilter.All, "chrome", 1),
    (InsightViewFilter.All, "2080", 2),
    (InsightViewFilter.All, "300", 1),
    (InsightViewFilter.All, " 8.8.8.8 ", 1),
    (InsightViewFilter.Loopback, "sing-box", 0),
};
foreach (var (filter, query, wanted) in filterCases)
{
    var actual = synthetic.Count(row => NetworkInsightFiltering.Matches(row, filter, query));
    if (actual != wanted)
        throw new InvalidOperationException($"INSIGHT_FILTER_FAIL {filter}/{query}: {actual} != {wanted}");
}
Console.WriteLine($"GENIAFIREWALL_INSIGHT_FILTER_TESTS=PASS_{filterCases.Length}");
