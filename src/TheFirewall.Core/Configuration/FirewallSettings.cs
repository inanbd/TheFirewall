using System.Text.Json.Serialization;

namespace TheFirewall.Core.Configuration;

/// <summary>All user-configurable settings. Persisted as JSON in %ProgramData%\TheFirewall\settings.json.</summary>
public sealed class FirewallSettings
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    /// <summary>Master switch. When off, failed logins are still recorded but nothing is banned or blocked.</summary>
    public bool ProtectionEnabled { get; set; } = true;

    public BanPolicy BanPolicy { get; set; } = new();

    public UserNamePolicy UserNames { get; set; } = new();

    /// <summary>Addresses that are never banned.</summary>
    public List<AddressEntry> Whitelist { get; set; } = [];

    /// <summary>Optional regular expression; matching IP addresses are never banned.</summary>
    public string WhitelistRegex { get; set; } = string.Empty;

    /// <summary>Addresses that are always blocked.</summary>
    public List<AddressEntry> Blacklist { get; set; } = [];

    /// <summary>Optional regular expression; a failed login whose IP address or user name matches is banned immediately.</summary>
    public string BlacklistRegex { get; set; } = string.Empty;

    public List<CustomFirewallRule> CustomRules { get; set; } = [];

    /// <summary>Per built-in source overrides (enabled state and threshold), keyed by source id.</summary>
    public Dictionary<string, SourceOverride> SourceOverrides { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>User-defined login sources.</summary>
    public List<LogSourceDefinition> CustomSources { get; set; } = [];

    public CountryBlockingSettings CountryBlocking { get; set; } = new();

    public List<ThreatFeed> ThreatFeeds { get; set; } = ThreatFeed.CreateDefaults();

    public NotificationSettings Notifications { get; set; } = new();

    public ActionSettings Actions { get; set; } = new();

    public GeneralSettings General { get; set; } = new();
}

public sealed class BanPolicy
{
    /// <summary>Number of failed logins before the address is banned.</summary>
    public int FailedAttemptsBeforeBan { get; set; } = 5;

    /// <summary>Failed attempts older than this are forgotten (the counter starts again).</summary>
    public TimeSpan FailedAttemptWindow { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Ban durations. The first ban uses the first entry, a repeat offender the next one, and so on.
    /// <see cref="TimeSpan.Zero"/> means permanent.
    /// </summary>
    public List<TimeSpan> BanDurations { get; set; } = [TimeSpan.FromDays(1), TimeSpan.FromDays(7), TimeSpan.FromDays(30)];

    /// <summary>How long a ban history is remembered for escalation once an address goes quiet.</summary>
    public TimeSpan RepeatOffenderMemory { get; set; } = TimeSpan.FromDays(90);

    /// <summary>When true, an address starts again from zero failed attempts after its ban expires.</summary>
    public bool ResetFailedAttemptsAfterUnban { get; set; } = true;

    /// <summary>Attempts that arrive faster than this from the same address count only once.</summary>
    public TimeSpan MinimumTimeBetweenFailedAttempts { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Whether private/LAN addresses (10.x, 192.168.x, ...) can be banned.</summary>
    public bool ProcessInternalAddresses { get; set; }

    /// <summary>Clear the failed attempt counter of an address when it logs in successfully.</summary>
    public bool ClearFailedAttemptsOnSuccessfulLogin { get; set; }
}

public sealed class UserNamePolicy
{
    /// <summary>User names are cut at the first of these characters ("bob@contoso.com" becomes "bob").</summary>
    public string TruncateUserNameChars { get; set; } = "@";

    /// <summary>Known/legitimate user names. They get a more forgiving threshold.</summary>
    public List<string> AllowedUserNames { get; set; } = [];

    /// <summary>Typos within this edit distance of an allowed user name are treated as allowed.</summary>
    public int AllowedUserNameEditDistance { get; set; } = 2;

    public int FailedAttemptsBeforeBanForAllowedUserNames { get; set; } = 20;

    /// <summary>When true and <see cref="AllowedUserNames"/> is not empty, any other user name is banned on the first attempt.</summary>
    public bool BanUnknownUserNamesImmediately { get; set; }

    /// <summary>User names that cause an immediate ban (for example "admin", "root", "test").</summary>
    public List<string> InstantBanUserNames { get; set; } = [];
}

public sealed class AddressEntry
{
    public string Value { get; set; } = string.Empty;

    public string Comment { get; set; } = string.Empty;

    public DateTimeOffset AddedUtc { get; set; } = DateTimeOffset.UtcNow;
}

[JsonConverter(typeof(JsonStringEnumConverter<RuleAction>))]
public enum RuleAction
{
    Block,
    Allow,
}

[JsonConverter(typeof(JsonStringEnumConverter<RuleDirection>))]
public enum RuleDirection
{
    Inbound,
    Outbound,
}

[JsonConverter(typeof(JsonStringEnumConverter<RuleProtocol>))]
public enum RuleProtocol
{
    Any,
    Tcp,
    Udp,
    IcmpV4,
    IcmpV6,
}

[Flags]
[JsonConverter(typeof(JsonStringEnumConverter<RuleProfiles>))]
public enum RuleProfiles
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
    All = Domain | Private | Public,
}

/// <summary>A user-defined Windows Firewall rule managed by TheFirewall.</summary>
public sealed class CustomFirewallRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..10];

    public string Name { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    public RuleAction Action { get; set; } = RuleAction.Block;

    public RuleDirection Direction { get; set; } = RuleDirection.Inbound;

    public RuleProtocol Protocol { get; set; } = RuleProtocol.Any;

    /// <summary>Comma separated ports or ranges, e.g. "80,443,8000-8100". Empty means any.</summary>
    public string LocalPorts { get; set; } = string.Empty;

    public string RemotePorts { get; set; } = string.Empty;

    /// <summary>Comma separated addresses, CIDR blocks or ranges. Empty means any address.</summary>
    public string RemoteAddresses { get; set; } = string.Empty;

    /// <summary>Optional full path of a program the rule applies to.</summary>
    public string ProgramPath { get; set; } = string.Empty;

    public RuleProfiles Profiles { get; set; } = RuleProfiles.All;

    public CustomFirewallRule Clone() => (CustomFirewallRule)MemberwiseClone();
}

public sealed class SourceOverride
{
    public bool? Enabled { get; set; }

    /// <summary>Failed attempts before ban for this source, 0 to use the global setting.</summary>
    public int FailedAttemptsBeforeBan { get; set; }
}

[JsonConverter(typeof(JsonStringEnumConverter<CountryBlockingMode>))]
public enum CountryBlockingMode
{
    Off,
    BlockSelected,
    AllowOnlySelected,
}

public sealed class CountryBlockingSettings
{
    public CountryBlockingMode Mode { get; set; } = CountryBlockingMode.Off;

    /// <summary>ISO 3166-1 alpha-2 country codes.</summary>
    public List<string> Countries { get; set; } = [];

    /// <summary>Local ports the country rule applies to (e.g. "3389,22"). Empty means all ports.</summary>
    public string Ports { get; set; } = string.Empty;

    public bool AutoUpdateDatabase { get; set; } = true;
}

public sealed class ThreatFeed
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..10];

    public string Name { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;

    public bool Enabled { get; set; }

    public int RefreshHours { get; set; } = 24;

    public int MaxEntries { get; set; } = 50_000;

    public static List<ThreatFeed> CreateDefaults() =>
    [
        new() { Id = "et-compromised", Name = "Emerging Threats - compromised hosts", Url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt" },
        new() { Id = "spamhaus-drop", Name = "Spamhaus DROP (hijacked networks)", Url = "https://www.spamhaus.org/drop/drop_v4.json" },
        new() { Id = "blocklist-de", Name = "blocklist.de - all attackers (last 48h)", Url = "https://lists.blocklist.de/lists/all.txt" },
        new() { Id = "cins-army", Name = "CINS Army bad guys", Url = "https://cinsscore.com/list/ci-badguys.txt" },
        new() { Id = "ipsum-3", Name = "IPsum level 3 (on 3+ blacklists)", Url = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" },
    ];
}

public sealed class NotificationSettings
{
    public bool NotifyOnBan { get; set; } = true;

    public bool NotifyOnUnban { get; set; }

    public bool NotifyOnSuccessfulLogin { get; set; }

    public bool NotifyOnServiceProblems { get; set; } = true;
}

/// <summary>External programs to run. Placeholders: {ip}, {user}, {source}, {count}, {log}, {reason}, {duration}.</summary>
public sealed class ActionSettings
{
    public string RunOnBan { get; set; } = string.Empty;

    public string RunOnUnban { get; set; } = string.Empty;

    public string RunOnSuccessfulLogin { get; set; } = string.Empty;
}

public sealed class GeneralSettings
{
    /// <summary>Prefix of every Windows Firewall rule created by TheFirewall. Letters, digits and underscore only.</summary>
    public string FirewallRulePrefix { get; set; } = "TheFirewall_";

    /// <summary>How often housekeeping runs (unbans, firewall sync, feed refresh).</summary>
    public TimeSpan CycleTime { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Activity history kept for the dashboard and activity feed.</summary>
    public int ActivityRetentionDays { get; set; } = 30;

    /// <summary>Remove all bans when the service starts.</summary>
    public bool ClearBansOnStartup { get; set; }

    /// <summary>
    /// Make sure Windows records failed logons in the Security log (audit policy "Logon: Failure").
    /// Without it RDP/SMB failures (event 4625) are never logged and cannot be detected.
    /// </summary>
    public bool EnsureLogonFailureAuditing { get; set; } = true;

    /// <summary>
    /// Also create an allow rule for whitelisted addresses. This opens every port to them, which is only
    /// useful when Windows Firewall blocks inbound traffic by default and you want trusted hosts to bypass it.
    /// </summary>
    public bool WhitelistOpensAllPorts { get; set; }
}
