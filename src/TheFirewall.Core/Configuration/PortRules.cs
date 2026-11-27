using System.Globalization;
using System.Text.Json.Serialization;

namespace TheFirewall.Core.Configuration;

/// <summary>Who may connect to a port managed on the Ports page.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<PortAccess>))]
public enum PortAccess
{
    /// <summary>Open: anyone may connect (bans and blocked countries still apply).</summary>
    Everyone,

    /// <summary>Everyone except the listed addresses and countries, the whitelist and the local network is blocked.</summary>
    Restricted,

    /// <summary>Closed: everyone except the whitelist and the local network is blocked.</summary>
    Nobody,
}

[Flags]
[JsonConverter(typeof(JsonStringEnumConverter<WeekDays>))]
public enum WeekDays
{
    None = 0,
    Monday = 1,
    Tuesday = 2,
    Wednesday = 4,
    Thursday = 8,
    Friday = 16,
    Saturday = 32,
    Sunday = 64,
    Weekdays = Monday | Tuesday | Wednesday | Thursday | Friday,
    Weekend = Saturday | Sunday,
    All = Weekdays | Weekend,
}

/// <summary>Weekly hours during which a port follows its access setting; outside them it is closed.</summary>
public sealed class PortSchedule
{
    public bool Enabled { get; set; }

    public WeekDays Days { get; set; } = WeekDays.Weekdays;

    /// <summary>Start time (computer's local time, "HH:mm").</summary>
    public string From { get; set; } = "08:00";

    /// <summary>End time ("HH:mm"). Earlier than <see cref="From"/> means the window runs past midnight; equal means all day.</summary>
    public string To { get; set; } = "18:00";

    public PortSchedule Clone() => (PortSchedule)MemberwiseClone();

    public static bool TryParseTime(string? text, out TimeOnly time) =>
        TimeOnly.TryParseExact(text?.Trim(), ["H:mm", "HH:mm"], CultureInfo.InvariantCulture, DateTimeStyles.None, out time);

    /// <summary>True when <paramref name="local"/> (local time) falls inside the open window.</summary>
    public bool IsOpenAt(DateTime local)
    {
        if (!TryParseTime(From, out var from) || !TryParseTime(To, out var to))
        {
            return false;
        }

        var time = TimeOnly.FromDateTime(local);
        bool today = HasDay(local.DayOfWeek);
        if (from == to)
        {
            return today;
        }

        if (from < to)
        {
            return today && time >= from && time < to;
        }

        // Overnight window, e.g. 22:00-06:00: the evening part belongs to today, the early hours to yesterday's window.
        return (today && time >= from) || (HasDay(local.AddDays(-1).DayOfWeek) && time < to);
    }

    public bool HasDay(DayOfWeek day) => (Days & ToFlag(day)) != 0;

    public static WeekDays ToFlag(DayOfWeek day) => day switch
    {
        DayOfWeek.Monday => WeekDays.Monday,
        DayOfWeek.Tuesday => WeekDays.Tuesday,
        DayOfWeek.Wednesday => WeekDays.Wednesday,
        DayOfWeek.Thursday => WeekDays.Thursday,
        DayOfWeek.Friday => WeekDays.Friday,
        DayOfWeek.Saturday => WeekDays.Saturday,
        _ => WeekDays.Sunday,
    };
}

/// <summary>A port (or port range) whose access TheFirewall manages.</summary>
public sealed class PortRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..10];

    /// <summary>Friendly name, e.g. "Remote Desktop".</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>TCP, UDP, or Any for both.</summary>
    public RuleProtocol Protocol { get; set; } = RuleProtocol.Tcp;

    /// <summary>Ports or ranges, e.g. "3389" or "8000-8100,8443".</summary>
    public string Ports { get; set; } = string.Empty;

    public PortAccess Access { get; set; } = PortAccess.Everyone;

    /// <summary>For <see cref="PortAccess.Restricted"/>: addresses, CIDR blocks or ranges that may connect.</summary>
    public string AllowedAddresses { get; set; } = string.Empty;

    /// <summary>For <see cref="PortAccess.Restricted"/>: country codes whose addresses may connect.</summary>
    public List<string> AllowedCountries { get; set; } = [];

    public PortSchedule Schedule { get; set; } = new();

    /// <summary>When set and in the future, the port is open to everyone until then, whatever the other settings say.</summary>
    public DateTimeOffset? OpenUntilUtc { get; set; }

    public PortRule Clone()
    {
        var copy = (PortRule)MemberwiseClone();
        copy.AllowedCountries = [.. AllowedCountries];
        copy.Schedule = Schedule.Clone();
        return copy;
    }
}

/// <summary>Where a port's current access comes from.</summary>
public enum PortStateReason
{
    /// <summary>The port's own access setting.</summary>
    Setting,

    /// <summary>Opened for a while with "Open for…".</summary>
    TemporarilyOpen,

    /// <summary>Closed because the current time is outside its schedule.</summary>
    OutsideSchedule,
}

/// <param name="Access">Who may connect right now.</param>
/// <param name="Reason">Why.</param>
/// <param name="NextChangeUtc">When the access changes by itself (end of a temporary opening or a schedule boundary), if known.</param>
public sealed record PortState(PortAccess Access, PortStateReason Reason, DateTimeOffset? NextChangeUtc);

public static class PortPolicy
{
    /// <summary>The access a port has at <paramref name="now"/>; schedules use the <paramref name="zone"/> local time.</summary>
    public static PortState Evaluate(PortRule rule, DateTimeOffset now, TimeZoneInfo zone)
    {
        if (rule.OpenUntilUtc is { } until && until > now)
        {
            return new PortState(PortAccess.Everyone, PortStateReason.TemporarilyOpen, until);
        }

        if (!rule.Schedule.Enabled)
        {
            return new PortState(rule.Access, PortStateReason.Setting, null);
        }

        var local = TimeZoneInfo.ConvertTime(now, zone).DateTime;
        bool open = rule.Schedule.IsOpenAt(local);
        var next = NextScheduleChange(rule.Schedule, local, open, zone);
        return open
            ? new PortState(rule.Access, PortStateReason.Setting, next)
            : new PortState(PortAccess.Nobody, PortStateReason.OutsideSchedule, next);
    }

    /// <summary>A key that changes whenever the effective access of any port changes (used to re-apply firewall rules).</summary>
    public static string StateKey(IEnumerable<PortRule> rules, DateTimeOffset now, TimeZoneInfo zone) =>
        string.Join('|', rules.Select(r => r.Id + ":" + Evaluate(r, now, zone).Access));

    private static DateTimeOffset? NextScheduleChange(PortSchedule schedule, DateTime local, bool openNow, TimeZoneInfo zone)
    {
        if (!PortSchedule.TryParseTime(schedule.From, out var from) || !PortSchedule.TryParseTime(schedule.To, out var to) ||
            schedule.Days == WeekDays.None)
        {
            return null;
        }

        var candidates = new List<DateTime>();
        for (int day = 0; day <= 8; day++)
        {
            var date = local.Date.AddDays(day);
            candidates.Add(date + from.ToTimeSpan());
            candidates.Add(date + to.ToTimeSpan());
            candidates.Add(date);
        }

        foreach (var candidate in candidates.Where(c => c > local).Distinct().Order())
        {
            if (schedule.IsOpenAt(candidate) != openNow)
            {
                try
                {
                    return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(candidate, DateTimeKind.Unspecified), zone), TimeSpan.Zero);
                }
                catch (ArgumentException)
                {
                    // The time does not exist (daylight saving gap): try the next one.
                }
            }
        }

        return null;
    }
}
