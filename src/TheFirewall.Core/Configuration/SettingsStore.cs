using System.Text.Json;
using Microsoft.Extensions.Logging;
using TheFirewall.Core.Firewall;
using TheFirewall.Core.Ipc;
using TheFirewall.Core.Monitoring;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Configuration;

/// <summary>Loads, validates and atomically saves <see cref="FirewallSettings"/>.</summary>
public sealed class SettingsStore(string path, ILogger logger)
{
    public string FilePath { get; } = path;

    public FirewallSettings Load()
    {
        if (!File.Exists(FilePath))
        {
            var defaults = new FirewallSettings();
            TrySave(defaults);
            return defaults;
        }

        try
        {
            var json = File.ReadAllText(FilePath);
            var settings = JsonSerializer.Deserialize<FirewallSettings>(json, IpcJson.SettingsOptions) ?? new FirewallSettings();
            Normalize(settings);
            return settings;
        }
        catch (Exception ex)
        {
            var backup = FilePath + ".invalid-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture);
            logger.LogError(ex, "Settings file {Path} is invalid; it was renamed to {Backup} and defaults are used", FilePath, backup);
            try
            {
                File.Move(FilePath, backup, overwrite: true);
            }
            catch (IOException)
            {
            }

            return new FirewallSettings();
        }
    }

    public void Save(FirewallSettings settings)
    {
        Normalize(settings);
        var directory = Path.GetDirectoryName(Path.GetFullPath(FilePath));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(settings, IpcJson.SettingsOptions));
        if (File.Exists(FilePath))
        {
            File.Copy(FilePath, FilePath + ".bak", overwrite: true);
        }

        File.Move(temp, FilePath, overwrite: true);
    }

    private void TrySave(FirewallSettings settings)
    {
        try
        {
            Save(settings);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to write default settings to {Path}", FilePath);
        }
    }

    public static FirewallSettings Clone(FirewallSettings settings) =>
        JsonSerializer.Deserialize<FirewallSettings>(JsonSerializer.Serialize(settings, IpcJson.SettingsOptions), IpcJson.SettingsOptions)!;

    /// <summary>Fixes values that would break the service (negative numbers, duplicate ids...).</summary>
    public static void Normalize(FirewallSettings s)
    {
        s.SchemaVersion = FirewallSettings.CurrentSchemaVersion;
        s.BanPolicy ??= new BanPolicy();
        s.UserNames ??= new UserNamePolicy();
        s.Whitelist ??= [];
        s.Blacklist ??= [];
        s.CustomRules ??= [];
        s.SourceOverrides ??= new Dictionary<string, SourceOverride>(StringComparer.OrdinalIgnoreCase);
        s.CustomSources ??= [];
        s.CountryBlocking ??= new CountryBlockingSettings();
        s.ThreatFeeds ??= [];
        s.Notifications ??= new NotificationSettings();
        s.Actions ??= new ActionSettings();
        s.General ??= new GeneralSettings();
        s.WhitelistRegex ??= string.Empty;
        s.BlacklistRegex ??= string.Empty;

        if (s.SourceOverrides.Comparer != StringComparer.OrdinalIgnoreCase)
        {
            s.SourceOverrides = new Dictionary<string, SourceOverride>(s.SourceOverrides, StringComparer.OrdinalIgnoreCase);
        }

        var p = s.BanPolicy;
        p.FailedAttemptsBeforeBan = Math.Clamp(p.FailedAttemptsBeforeBan, 1, 10_000);
        if (p.FailedAttemptWindow < TimeSpan.FromMinutes(1))
        {
            p.FailedAttemptWindow = TimeSpan.FromMinutes(1);
        }

        p.BanDurations = (p.BanDurations ?? []).Select(d => d < TimeSpan.Zero ? TimeSpan.Zero : d).Take(20).ToList();
        if (p.BanDurations.Count == 0)
        {
            p.BanDurations.Add(TimeSpan.FromDays(1));
        }

        if (p.MinimumTimeBetweenFailedAttempts < TimeSpan.Zero)
        {
            p.MinimumTimeBetweenFailedAttempts = TimeSpan.Zero;
        }

        if (p.RepeatOffenderMemory < TimeSpan.Zero)
        {
            p.RepeatOffenderMemory = TimeSpan.Zero;
        }

        s.UserNames.AllowedUserNames ??= [];
        s.UserNames.InstantBanUserNames ??= [];
        s.UserNames.TruncateUserNameChars ??= string.Empty;
        s.UserNames.FailedAttemptsBeforeBanForAllowedUserNames = Math.Clamp(s.UserNames.FailedAttemptsBeforeBanForAllowedUserNames, 1, 10_000);
        s.UserNames.AllowedUserNameEditDistance = Math.Clamp(s.UserNames.AllowedUserNameEditDistance, 0, 5);

        var g = s.General;
        g.FirewallRulePrefix = FirewallPlanner.SanitizePrefix(g.FirewallRulePrefix);
        if (g.CycleTime < TimeSpan.FromSeconds(5) || g.CycleTime > TimeSpan.FromMinutes(10))
        {
            g.CycleTime = TimeSpan.FromSeconds(15);
        }

        g.ActivityRetentionDays = Math.Clamp(g.ActivityRetentionDays, 1, 3650);

        s.CountryBlocking.Countries = (s.CountryBlocking.Countries ?? []).Where(c => !string.IsNullOrWhiteSpace(c))
            .Select(c => c.Trim().ToUpperInvariant()).Distinct().ToList();
        s.CountryBlocking.Ports ??= string.Empty;

        EnsureUniqueIds(s.CustomRules, r => r.Id, (r, id) => r.Id = id);
        EnsureUniqueIds(s.CustomSources, r => r.Id, (r, id) => r.Id = id);
        EnsureUniqueIds(s.ThreatFeeds, r => r.Id, (r, id) => r.Id = id);

        foreach (var source in s.CustomSources)
        {
            source.Expressions ??= [];
            source.PollIntervalSeconds = Math.Clamp(source.PollIntervalSeconds, 1, 3600);
            if (BuiltInSources.Find(source.Id) is not null)
            {
                source.Id = "custom-" + Guid.NewGuid().ToString("N")[..8];
            }
        }

        foreach (var feed in s.ThreatFeeds)
        {
            feed.RefreshHours = Math.Clamp(feed.RefreshHours, 1, 24 * 30);
            feed.MaxEntries = Math.Clamp(feed.MaxEntries, 1, 1_000_000);
        }
    }

    /// <summary>Returns human readable problems; an empty list means the settings can be saved.</summary>
    public static List<string> Validate(FirewallSettings s)
    {
        var errors = new List<string>();
        foreach (var entry in s.Whitelist)
        {
            if (!IPAddressRange.TryParse(entry.Value, out _))
            {
                errors.Add($"Whitelist: '{entry.Value}' is not a valid address, CIDR block or range.");
            }
        }

        foreach (var entry in s.Blacklist)
        {
            if (!IPAddressRange.TryParse(entry.Value, out _))
            {
                errors.Add($"Blacklist: '{entry.Value}' is not a valid address, CIDR block or range.");
            }
        }

        AddRegexError(errors, "Whitelist pattern", s.WhitelistRegex);
        AddRegexError(errors, "Blacklist pattern", s.BlacklistRegex);

        foreach (var rule in s.CustomRules)
        {
            var label = string.IsNullOrWhiteSpace(rule.Name) ? rule.Id : rule.Name;
            if (string.IsNullOrWhiteSpace(rule.Name))
            {
                errors.Add($"Firewall rule {rule.Id}: a name is required.");
            }

            if (!FirewallPlanner.TryNormalizePorts(rule.LocalPorts, out _, out var portError) ||
                !FirewallPlanner.TryNormalizePorts(rule.RemotePorts, out _, out portError))
            {
                errors.Add($"Firewall rule '{label}': {portError}");
            }

            if ((!string.IsNullOrWhiteSpace(rule.LocalPorts) || !string.IsNullOrWhiteSpace(rule.RemotePorts)) &&
                rule.Protocol is not (RuleProtocol.Tcp or RuleProtocol.Udp))
            {
                errors.Add($"Firewall rule '{label}': ports can only be used with TCP or UDP.");
            }

            var invalid = new List<string>();
            foreach (var token in rule.RemoteAddresses.Split([',', ';', '\n', '\r', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!IPAddressRange.TryParse(token, out _) && !FirewallPlanner.IsAddressKeyword(token))
                {
                    invalid.Add(token);
                }
            }

            if (invalid.Count > 0)
            {
                errors.Add($"Firewall rule '{label}': invalid address(es) {string.Join(", ", invalid)}.");
            }
        }

        foreach (var source in s.CustomSources)
        {
            var label = string.IsNullOrWhiteSpace(source.Name) ? source.Id : source.Name;
            if (string.IsNullOrWhiteSpace(source.Name))
            {
                errors.Add($"Login source {source.Id}: a name is required.");
            }

            if (source.Kind == LogSourceKind.TextFile)
            {
                if (string.IsNullOrWhiteSpace(source.PathMasks))
                {
                    errors.Add($"Login source '{label}': at least one log file path is required.");
                }

                if (string.IsNullOrWhiteSpace(source.Regex))
                {
                    errors.Add($"Login source '{label}': a regular expression is required.");
                }

                AddRegexError(errors, $"Login source '{label}'", source.Regex);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(source.LogName))
                {
                    errors.Add($"Login source '{label}': an event log name is required.");
                }

                if (source.Expressions.Count == 0)
                {
                    errors.Add($"Login source '{label}': add at least one expression that captures the IP address.");
                }

                foreach (var expression in source.Expressions)
                {
                    AddRegexError(errors, $"Login source '{label}'", expression.Regex);
                    try
                    {
                        System.Xml.XPath.XPathExpression.Compile(expression.XPath);
                    }
                    catch (System.Xml.XPath.XPathException ex)
                    {
                        errors.Add($"Login source '{label}': invalid XPath '{expression.XPath}': {ex.Message}");
                    }
                }
            }
        }

        foreach (var feed in s.ThreatFeeds)
        {
            if (!Uri.TryCreate(feed.Url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                errors.Add($"Threat feed '{feed.Name}': '{feed.Url}' is not a valid http(s) URL.");
            }
        }

        if (!FirewallPlanner.TryNormalizePorts(s.CountryBlocking.Ports, out _, out var countryPortError))
        {
            errors.Add($"Country blocking: {countryPortError}");
        }

        return errors;
    }

    private static void AddRegexError(List<string> errors, string label, string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return;
        }

        var error = LoginRegex.Validate(pattern);
        if (error is not null)
        {
            errors.Add($"{label}: invalid regular expression: {error}");
        }
    }

    private static void EnsureUniqueIds<T>(List<T> items, Func<T, string> get, Action<T, string> set)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            var id = get(item);
            if (string.IsNullOrWhiteSpace(id) || !seen.Add(id))
            {
                id = Guid.NewGuid().ToString("N")[..10];
                set(item, id);
                seen.Add(id);
            }
        }
    }
}
