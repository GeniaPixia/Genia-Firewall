using System.Globalization;
using System.Windows;
using GeniaFirewall.Intelligence.Desktop;

namespace GeniaFirewall.Intelligence.Smoke;

/// <summary>
/// Standalone read-only GUI for user smoke testing. References ONLY the
/// Intelligence.Desktop and Intelligence projects, not GeniaFirewall or WFP.
/// Does not request elevation and has no auto-start or background loop.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
        var ru = string.Equals(CultureInfo.CurrentUICulture.TwoLetterISOLanguageName,
            "ru", StringComparison.OrdinalIgnoreCase);
        var window = new IntelligenceWindow(ru)
        {
            Title = "GeniaFirewall Intelligence 0.8.0 — READ-ONLY TEST"
        };
        app.Run(window);
    }
}
