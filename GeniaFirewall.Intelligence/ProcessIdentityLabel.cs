namespace GeniaFirewall.Intelligence;

/// <summary>
/// A process name without its verified image path is only an OS-provided
/// name, not an authenticated executable filename or trust verdict.
/// </summary>
public static class ProcessIdentityLabel
{
    public static string NameOnlyOrPid(int pid, string? name) =>
        string.IsNullOrWhiteSpace(name) ? $"PID {pid}" : name.Trim();
}
