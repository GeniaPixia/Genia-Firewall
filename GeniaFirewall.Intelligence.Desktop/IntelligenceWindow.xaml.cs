using System.Windows;
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
            ResultText.Text = "Not collecting. Click Refresh to observe once.";
            var columns = ObservationsGrid.Columns;
            columns[0].Header = "Process";
            columns[1].Header = "PID";
            columns[2].Header = "Protocol";
            columns[3].Header = "Scope";
            columns[4].Header = "Local endpoint";
            columns[5].Header = "Remote endpoint";
            columns[6].Header = "State";
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
            // One ItemsSource change avoids thousands of UI-thread collection notifications.
            var visible = snapshot.Connections.Select(r => new InsightRow(r, _ru)).ToArray();
            ObservationsGrid.ItemsSource = visible;

            var external = snapshot.Connections.Count(c => c.Scope == ObservationScope.ExternalCandidate);
            var loopback = snapshot.Connections.Count(c => c.Scope == ObservationScope.Loopback);
            var privateCount = snapshot.Connections.Count(c => c.Scope == ObservationScope.PrivateOrLan);
            var udp = snapshot.Connections.Count(c => c.Scope == ObservationScope.LocalUdpSocket);
            var summary = _ru
                ? $"Строк: {visible.Length} · внешние TCP*: {external} · loopback: {loopback} · LAN: {privateCount} · UDP-сокеты: {udp}"
                : $"Rows: {visible.Length} · external TCP*: {external} · loopback: {loopback} · LAN: {privateCount} · UDP sockets: {udp}";
            if (!snapshot.Complete)
                summary += (_ru ? " · частичный снимок: " : " · partial snapshot: ") +
                           string.Join("; ", snapshot.Issues);
            if (snapshot.Truncated)
                summary += _ru ? " · список ограничен 2000 строками" : " · limited to 2000 rows";
            ResultText.Text = summary;
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

        public InsightRow(NetworkObservation source, bool ru)
        {
            Pid = source.Pid;
            ProcessName = source.ProcessName;
            ExecutablePath = source.ExecutablePath;
            Protocol = source.Protocol;
            LocalEndpoint = source.LocalEndpoint;
            RemoteEndpoint = source.RemoteEndpoint;
            State = source.State;
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
