using System.Windows;
using System.Windows.Controls;
using GeniaFirewall.Intelligence;

namespace GeniaFirewall.Intelligence.Desktop;

/// <summary>
/// Opt-in, single-snapshot view: no timer, no hooks, no policy mutations or persistence.
/// </summary>
public partial class IntelligenceWindow : Window
{
    private readonly NetworkInsightCollector _collector = new();
    private readonly bool _ru;
    private bool _refreshing;
    private NetworkInsightSnapshot? _lastSnapshot;
    private IReadOnlyDictionary<NetworkObservation, NetworkObservation> _peerPairs =
        new Dictionary<NetworkObservation, NetworkObservation>();

    public IntelligenceWindow(bool russian)
    {
        _ru = russian;
        InitializeComponent();
        if (!_ru)
        {
            SubtitleText.Text = "Read-only snapshot · firewall rules are never modified";
            ExplanationText.Text = "Click Refresh for one snapshot. An external endpoint does not prove telemetry. " +
                "Local proxy hops can hide the final destination; UDP tables show local sockets only.";
            RefreshButton.Content = "Refresh";
            CloseButton.Content = "Close";
            FilterLabel.Text = "Show";
            SearchLabel.Text = "Search";
            SearchTextBox.ToolTip = "Find by process name, PID, path or endpoint";
            var labels = new[] { "All connections", "External TCP", "Loopback", "LAN (TCP)", "TCP listeners", "UDP sockets", "Unknown" };
            for (var i = 0; i < labels.Length; i++)
                if (ScopeFilterComboBox.Items[i] is ComboBoxItem item)
                    item.Content = labels[i];
            ResultText.Text = "Not collecting. Click Refresh to observe once.";
            var columns = ObservationsGrid.Columns;
            columns[0].Header = "Process";
            columns[1].Header = "PID";
            columns[2].Header = "Protocol";
            columns[3].Header = "Scope";
            columns[4].Header = "Local endpoint";
            columns[5].Header = "Remote endpoint";
            columns[6].Header = "Possible peer";
            columns[7].Header = "State";
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (_refreshing) return;
        _refreshing = true;
        RefreshButton.IsEnabled = false;
        ResultText.Text = _ru ? "Чтение таблиц соединений Windows..." : "Reading Windows network tables...";
        try
        {
            var snapshot = await Task.Run(_collector.Collect);
            if (!IsLoaded) return;
            _lastSnapshot = snapshot;
            _peerPairs = LoopbackPeerCorrelation.FindPeers(snapshot.Connections);
            ApplyFilter();

        }
        catch (Exception)
        {
            // Do not expose process paths in error dialogs or upload diagnostics.
            ResultText.Text = _ru ? "Не удалось получить снимок. Правила не менялись." :
                "Failed to read snapshot. Firewall rules were not changed.";
        }
        finally
        {
            _refreshing = false;
            RefreshButton.IsEnabled = true;
        }
    }

    private void ScopeFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded) ApplyFilter();
    }

    private void SearchText_Changed(object sender, TextChangedEventArgs e)
    {
        if (IsLoaded) ApplyFilter();
    }

    private void ApplyFilter()
    {
        if (_lastSnapshot is null || ScopeFilterComboBox is null || SearchTextBox is null)
            return;

        var tag = (ScopeFilterComboBox.SelectedItem as ComboBoxItem)?.Tag as string;
        if (!Enum.TryParse<InsightViewFilter>(tag, out var filter))
            filter = InsightViewFilter.All;
        var filtered = _lastSnapshot.Connections
            .Where(row => NetworkInsightFiltering.Matches(
                row, filter, SearchTextBox.Text,
                _peerPairs.TryGetValue(row, out var peer) ? peer.ProcessName : null))
            .Select(row => new InsightRow(row, _ru,
                _peerPairs.TryGetValue(row, out var peer) ? peer : null)).ToArray();
        ObservationsGrid.ItemsSource = filtered;

        var source = _lastSnapshot.Connections;
        var external = source.Count(row => row.Scope == ObservationScope.ExternalCandidate);
        var loopback = source.Count(row => row.Scope == ObservationScope.Loopback);
        var lan = source.Count(row => row.Scope == ObservationScope.PrivateOrLan);
        var udp = source.Count(row => row.Scope == ObservationScope.LocalUdpSocket);
        var listeners = source.Count(row => row.Scope == ObservationScope.Listener);
        var timestamp = _lastSnapshot.CapturedAt.ToLocalTime().ToString("HH:mm:ss");
        var candidatePairs = _peerPairs.Count / 2;
        var summary = _ru
            ? $"Показано {filtered.Length} из {source.Count} · внешний TCP*: {external} · Loopback: {loopback} · LAN TCP: {lan} · слушающие: {listeners} · UDP: {udp} · пар localhost*: {candidatePairs} · снимок {timestamp}"
            : $"Showing {filtered.Length} of {source.Count} · external TCP*: {external} · loopback: {loopback} · LAN TCP: {lan} · listeners: {listeners} · UDP: {udp} · local pairs*: {candidatePairs} · snapshot {timestamp}";
        if (!_lastSnapshot.Complete)
            summary += (_ru ? " · неполный снимок: " : " · partial snapshot: ") +
                string.Join("; ", _lastSnapshot.Issues);
        if (_lastSnapshot.Truncated)
            summary += _ru ? " · ограничено 2000 строками" : " · limited to 2000 rows";
        ResultText.Text = summary;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    public sealed class InsightRow
    {
        public int Pid { get; }
        public string ProcessName { get; }
        public string ExecutablePath { get; }
        public string Protocol { get; }
        public string LocalEndpoint { get; }
        public string RemoteEndpoint { get; }
        public string State { get; }
        public string ScopeDisplay { get; }
        public string PeerDisplay { get; }
        public string PeerTooltip { get; }

        public InsightRow(NetworkObservation source, bool ru, NetworkObservation? peer)
        {
            Pid = source.Pid;
            ProcessName = source.ProcessName;
            ExecutablePath = source.ExecutablePath;
            Protocol = source.Protocol;
            LocalEndpoint = source.LocalEndpoint;
            RemoteEndpoint = source.RemoteEndpoint;
            State = source.State;
            PeerDisplay = peer is null ? "—" : $"{peer.ProcessName} (PID {peer.Pid})";
            PeerTooltip = peer is null
                ? (ru ? "Однозначная обратная TCP-пара в снимке не найдена" : "No unambiguous reverse TCP row")
                : (ru
                    ? $"Возможная парная запись в том же снимке, не подтверждение маршрута: {peer.ProcessName}, PID {peer.Pid}"
                    : $"Possible reverse socket in the same snapshot, not proof of routing: {peer.ProcessName}, PID {peer.Pid}");
            ScopeDisplay = ru ? source.Scope switch
            {
                ObservationScope.ExternalCandidate => "Внешний TCP*",
                ObservationScope.Loopback => "Loopback",
                ObservationScope.PrivateOrLan => "LAN / частная",
                ObservationScope.LocalUdpSocket => "UDP-сокет",
                ObservationScope.Listener => "Слушающий",
                _ => "Не определено"
            } : source.Scope switch
            {
                ObservationScope.ExternalCandidate => "External TCP*",
                ObservationScope.Loopback => "Loopback",
                ObservationScope.PrivateOrLan => "LAN / private",
                ObservationScope.LocalUdpSocket => "UDP socket",
                ObservationScope.Listener => "Listener",
                _ => "Unknown"
            };
        }
    }
}
