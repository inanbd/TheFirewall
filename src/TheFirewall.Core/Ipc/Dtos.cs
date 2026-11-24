using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Feeds;
using TheFirewall.Core.Firewall;
using TheFirewall.Core.Monitoring;

namespace TheFirewall.Core.Ipc;

public sealed class HelloResponse
{
    public string ServiceVersion { get; set; } = string.Empty;

    public string MachineName { get; set; } = string.Empty;

    /// <summary>Whether the connected client may change settings.</summary>
    public bool IsAdministrator { get; set; }

    public string? UserName { get; set; }
}

public sealed class ServiceStatusDto
{
    public string Version { get; set; } = string.Empty;

    public string MachineName { get; set; } = string.Empty;

    public DateTimeOffset StartedUtc { get; set; }

    public bool ProtectionEnabled { get; set; }

    public long ActiveBans { get; set; }

    public string FirewallName { get; set; } = string.Empty;

    public FirewallProfileState FirewallProfiles { get; set; } = new();

    public int FirewallRuleCount { get; set; }

    public int BlockedEntryCount { get; set; }

    public DateTimeOffset? LastFirewallSyncUtc { get; set; }

    public string? FirewallError { get; set; }

    public bool GeoDatabaseAvailable { get; set; }

    public string? GeoDatabaseVersion { get; set; }

    public string? GeoDatabaseError { get; set; }

    public int ActiveSources { get; set; }

    public string DataDirectory { get; set; } = string.Empty;

    /// <summary>Problems the user should know about, e.g. a firewall profile that is switched off.</summary>
    public List<string> Warnings { get; set; } = [];
}

public sealed class SourceInfoDto
{
    public LogSourceDefinition Definition { get; set; } = new();

    public bool IsBuiltIn { get; set; }

    public SourceStatus Status { get; set; } = new();
}

public sealed class CountryDto
{
    public string Code { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string Region { get; set; } = string.Empty;

    public int RangeCount { get; set; }
}

public sealed class FeedInfoDto
{
    public ThreatFeed Feed { get; set; } = new();

    public ThreatFeedStatus Status { get; set; } = new();
}

public sealed class BanRequest
{
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>Minutes; null uses the normal ban duration, 0 bans permanently.</summary>
    public int? DurationMinutes { get; set; }

    public string? Reason { get; set; }
}

public sealed class UnbanRequest
{
    public List<string> IPAddresses { get; set; } = [];

    public bool AddToWhitelist { get; set; }

    public string? Comment { get; set; }
}

public sealed class ProtectionRequest
{
    public bool Enabled { get; set; }
}

public sealed class SaveSettingsResponse
{
    public bool Saved { get; set; }

    public List<string> Errors { get; set; } = [];
}

public sealed class LookupRequest
{
    public string IPAddress { get; set; } = string.Empty;
}

public sealed class LookupResult
{
    public string IPAddress { get; set; } = string.Empty;

    public string? Country { get; set; }

    public bool IsInternal { get; set; }

    public bool IsWhitelisted { get; set; }

    public bool IsBlacklisted { get; set; }

    public IPRecord? Record { get; set; }

    public List<ActivityEntry> RecentActivity { get; set; } = [];
}

public sealed class SourceTestRequest
{
    public LogSourceDefinition Definition { get; set; } = new();

    /// <summary>Log lines for text-file sources, or the XML of an event for event-log sources.</summary>
    public string Sample { get; set; } = string.Empty;
}

public sealed class SourceTestMatch
{
    public string IPAddress { get; set; } = string.Empty;

    public string? UserName { get; set; }

    public string? Source { get; set; }

    public string? Log { get; set; }

    public DateTimeOffset? Timestamp { get; set; }
}

public sealed class SourceTestResult
{
    public string? Error { get; set; }

    public List<SourceTestMatch> Matches { get; set; } = [];
}

public sealed class WatchedListRequest
{
    public int Limit { get; set; } = 1000;
}

/// <summary>Settings plus ban list, used for export/import.</summary>
public sealed class ExportBundle
{
    public string Product { get; set; } = "TheFirewall";

    public string Version { get; set; } = string.Empty;

    public DateTimeOffset ExportedUtc { get; set; } = DateTimeOffset.UtcNow;

    public FirewallSettings? Settings { get; set; }

    public List<IPRecord>? Bans { get; set; }
}

public sealed class ImportBansRequest
{
    public List<IPRecord> Bans { get; set; } = [];
}
