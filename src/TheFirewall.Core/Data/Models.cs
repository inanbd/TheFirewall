using System.Text.Json.Serialization;

namespace TheFirewall.Core.Data;

/// <summary>Everything TheFirewall knows about one IP address.</summary>
public sealed class IPRecord
{
    public required string IPAddress { get; init; }

    public int FailedCount { get; set; }

    public DateTimeOffset? FirstFailedUtc { get; set; }

    public DateTimeOffset? LastFailedUtc { get; set; }

    public DateTimeOffset LastActivityUtc { get; set; }

    public bool IsBanned { get; set; }

    public DateTimeOffset? BanStartUtc { get; set; }

    /// <summary>When the ban ends; null while banned means permanent.</summary>
    public DateTimeOffset? BanEndUtc { get; set; }

    /// <summary>How many times the address has been banned (drives escalating ban durations).</summary>
    public int BanLevel { get; set; }

    public string? Source { get; set; }

    /// <summary>Recent user names tried from this address, comma separated (most recent first).</summary>
    public string? UserNames { get; set; }

    public string? LastLog { get; set; }

    public string? BanReason { get; set; }

    public bool Manual { get; set; }

    public string? Country { get; set; }

    public void AddUserName(string? userName)
    {
        if (string.IsNullOrWhiteSpace(userName))
        {
            return;
        }

        var names = (UserNames ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(n => !string.Equals(n, userName, StringComparison.OrdinalIgnoreCase))
            .Prepend(userName.Replace(",", string.Empty, StringComparison.Ordinal))
            .Take(8);
        UserNames = string.Join(", ", names);
    }
}

[JsonConverter(typeof(JsonStringEnumConverter<ActivityType>))]
public enum ActivityType
{
    FailedLogin = 1,
    SuccessfulLogin = 2,
    Banned = 3,
    Unbanned = 4,
    Info = 5,
    Warning = 6,

    /// <summary>A failed login that was not counted (whitelisted, internal address, protection paused...).</summary>
    Ignored = 7,
}

public sealed class ActivityEntry
{
    public long Id { get; set; }

    public DateTimeOffset TimeUtc { get; set; }

    public ActivityType Type { get; set; }

    public string? IPAddress { get; set; }

    public string? Country { get; set; }

    public string? Source { get; set; }

    public string? UserName { get; set; }

    public string? Message { get; set; }
}

public sealed class ActivityQuery
{
    public DateTimeOffset? SinceUtc { get; set; }

    public long? BeforeId { get; set; }

    public List<ActivityType>? Types { get; set; }

    public string? Search { get; set; }

    /// <summary>Exact IP address filter.</summary>
    public string? IPAddress { get; set; }

    public int Limit { get; set; } = 200;
}

public sealed class NamedCount
{
    public string Name { get; set; } = string.Empty;

    public long Count { get; set; }
}

public sealed class DashboardStats
{
    public long FailedLast24h { get; set; }

    public long BansLast24h { get; set; }

    public long SuccessfulLast24h { get; set; }

    public long ActiveBans { get; set; }

    public long WatchedAddresses { get; set; }

    public long TotalBansAllTime { get; set; }

    /// <summary>Failed attempts per hour for the last 24 hours, oldest first.</summary>
    public List<long> HourlyFailed { get; set; } = [];

    /// <summary>Bans per hour for the last 24 hours, oldest first.</summary>
    public List<long> HourlyBans { get; set; } = [];

    /// <summary>Failed attempts per day for the last 30 days, oldest first.</summary>
    public List<long> DailyFailed { get; set; } = [];

    public List<NamedCount> TopSources { get; set; } = [];

    public List<NamedCount> TopCountries { get; set; } = [];

    public List<NamedCount> TopUserNames { get; set; } = [];

    public List<NamedCount> TopAddresses { get; set; } = [];
}
