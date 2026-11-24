namespace TheFirewall.Core;

/// <summary>Locations of TheFirewall's data files.</summary>
public sealed record FirewallPaths(string DataDirectory)
{
    /// <summary>%ProgramData%\TheFirewall on Windows.</summary>
    public static FirewallPaths Default { get; } = new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TheFirewall"));

    public string SettingsFile => Path.Combine(DataDirectory, "settings.json");

    public string DatabaseFile => Path.Combine(DataDirectory, "thefirewall.db");

    public string GeoDirectory => Path.Combine(DataDirectory, "geoip");

    public string FeedsDirectory => Path.Combine(DataDirectory, "feeds");

    public string LogsDirectory => Path.Combine(DataDirectory, "logs");

    public string CustomLogsDirectory => Path.Combine(DataDirectory, "CustomLogs");
}
