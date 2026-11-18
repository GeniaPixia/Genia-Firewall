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
