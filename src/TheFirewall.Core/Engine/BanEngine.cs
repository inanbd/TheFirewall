using System.Globalization;
using System.Net;
using Microsoft.Extensions.Logging;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Monitoring;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Engine;

public sealed record BanEventArgs(IPRecord Record, string Reason, TimeSpan? Duration, string? UserName, string? Source, string? LogText);

/// <summary>
/// Counts failed logins per address and bans addresses that exceed the configured threshold.
/// All state lives in <see cref="FirewallDatabase"/>; this class is thread-safe.
/// </summary>
public sealed class BanEngine
{
    private readonly FirewallDatabase db;
    private readonly TimeProvider time;
    private readonly ILogger logger;
    private readonly Func<string, string?> countryLookup;
    private readonly object sync = new();
    private readonly Dictionary<string, RecentAttempts> recent = new(StringComparer.OrdinalIgnoreCase);
    private volatile PolicyContext context;

    /// <summary>
    /// Windows often reports one failed attempt in two logs (e.g. Security event 4625 and RdpCoreTS event 140).
    /// Failures from different sources for the same address within this window are treated as one attempt.
    /// </summary>
    internal static readonly TimeSpan SameAttemptWindow = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Remote Desktop clients often log a "failed" step while negotiating credentials (NLA) right before a
    /// successful sign-in. Failures this close before a successful sign-in from the same address belong to it.
    /// </summary>
    internal static readonly TimeSpan SignInHandshakeWindow = TimeSpan.FromSeconds(10);

    /// <summary>Administrators get two success events per sign-in (standard and elevated token); show them once.</summary>
    internal static readonly TimeSpan DuplicateSuccessWindow = TimeSpan.FromSeconds(10);

    public BanEngine(FirewallDatabase db, FirewallSettings settings, ILogger logger, TimeProvider? time = null, Func<string, string?>? countryLookup = null)
    {
        this.db = db;
        this.logger = logger;
        this.time = time ?? TimeProvider.System;
        this.countryLookup = countryLookup ?? (_ => null);
        context = new PolicyContext(settings);
    }

    /// <summary>Raised for every new activity entry (after it has been stored).</summary>
    public event Action<ActivityEntry>? ActivityAdded;

    /// <summary>Raised when an existing activity entry changed (e.g. the user name became known).</summary>
    public event Action<ActivityEntry>? ActivityUpdated;

    /// <summary>Raised when activity entries were removed (failed steps that turned out to be part of a sign-in).</summary>
    public event Action<IReadOnlyList<long>>? ActivityRemoved;

    public event Action<BanEventArgs>? AddressBanned;

    public event Action<IPRecord, string>? AddressUnbanned;

    public event Action<LoginEvent>? SuccessfulLogin;

    /// <summary>Raised when the set of banned addresses changed and the firewall should be updated.</summary>
    public event Action? BansChanged;

    public PolicyContext Context => context;

    public void UpdateSettings(FirewallSettings settings)
    {
        context = new PolicyContext(settings);
        ReleaseWhitelistedBans();
    }

    public void Process(LoginEvent evt)
    {
        var ctx = context;
        var settings = ctx.Settings;
        if (!IPUtility.TryParseAddress(evt.IPAddress, out var address))
        {
            return;
        }

        var ip = address.ToString();
        var now = time.GetUtcNow();
        var eventTime = evt.Timestamp > now ? now : evt.Timestamp;
        var userName = ctx.NormalizeUserName(evt.UserName);
        var country = countryLookup(ip);

        if (evt.Kind == LoginEventKind.Successful)
        {
            HandleSuccess(evt, ip, userName, country, eventTime, now);
            return;
        }

        if (!settings.BanPolicy.ProcessInternalAddresses && IPUtility.IsInternal(address))
        {
            RecordIgnoredFailure(evt, ip, country, userName, eventTime, now, "Failed login from a local network address (not counted).");
            return;
        }

        if (ctx.IsWhitelisted(address, ip))
        {
            RecordIgnoredFailure(evt, ip, country, userName, eventTime, now, "Failed login from a whitelisted address (not counted).");
            return;
        }

        BanEventArgs? banned = null;
        lock (sync)
        {
            var record = db.GetRecord(ip) ?? new IPRecord { IPAddress = ip, LastActivityUtc = now };
            record.Country ??= country;
            record.Source = evt.Source;
            record.AddUserName(userName);
            record.LastLog = evt.LogText;
            record.LastActivityUtc = now;

            var attempts = GetRecentAttempts(ip, eventTime);
            if (IsPartOfRecentSignIn(attempts, evt, eventTime))
            {
                // A failed step of a sign-in that already succeeded, reported late by another log.
                db.SaveRecord(record);
                return;
            }

            var sameAttempt = FindSameAttempt(attempts, evt, eventTime);
            if (sameAttempt is not null)
            {
                // The same attempt, reported by another log: do not count it again or add another row.
                sameAttempt.MergedSources.Add(evt.SourceId);
                MergeUserName(sameAttempt.Entry, userName);
            }

            if (record.IsBanned)
            {
                if (sameAttempt is null)
                {
                    record.FailedCount += Math.Max(1, evt.Count);
                    record.LastFailedUtc = eventTime;
                    var bannedEntry = AddActivity(ActivityType.FailedLogin, ip, country, evt.Source, userName,
                        "Failed login from an address that is already banned (the firewall rule may still be applying, or the port is reachable another way).", now);
                    attempts.Failures.Add(new RecentFailure(eventTime, evt.SourceId, evt.Source, bannedEntry, Counted: false));
                }

                db.SaveRecord(record);
                return;
            }

            var policy = settings.BanPolicy;
            if (record.LastFailedUtc is { } lastFailed && now - lastFailed > policy.FailedAttemptWindow)
            {
                record.FailedCount = 0;
                record.FirstFailedUtc = null;
            }

            bool duplicate = sameAttempt is not null;
            bool throttled = !duplicate && record.LastFailedUtc is { } previous &&
                             (eventTime - previous).Duration() < policy.MinimumTimeBetweenFailedAttempts && record.FailedCount > 0;
            if (!throttled && !duplicate)
            {
                record.FailedCount += Math.Max(1, evt.Count);
                record.FirstFailedUtc ??= eventTime;
            }

            if (record.LastFailedUtc is null || eventTime > record.LastFailedUtc)
            {
                record.LastFailedUtc = eventTime;
            }

            int threshold = evt.FailedAttemptsBeforeBan > 0 ? evt.FailedAttemptsBeforeBan : Math.Max(1, policy.FailedAttemptsBeforeBan);
            string? reason = null;

            if (userName is not null && ctx.InstantBanUserNames.Contains(userName))
            {
                reason = $"Tried the user name '{userName}', which is on the instant-ban list";
            }
            else if (ctx.MatchesBlacklistRegex(ip, userName))
            {
                reason = "Matched the blacklist pattern";
            }
            else if (ctx.IsBlacklisted(address))
            {
                reason = "Address is on the blacklist";
            }
            else if (userName is not null && ctx.AllowedUserNames.Count > 0)
            {
                if (ctx.IsAllowedUserName(userName))
                {
                    threshold = Math.Max(threshold, settings.UserNames.FailedAttemptsBeforeBanForAllowedUserNames);
                }
                else if (settings.UserNames.BanUnknownUserNamesImmediately)
                {
                    reason = $"Tried the unknown user name '{userName}'";
                }
            }

            if (reason is null && record.FailedCount >= threshold)
            {
                reason = string.Create(CultureInfo.InvariantCulture, $"{record.FailedCount} failed logins via {evt.Source}");
            }

            var message = string.Create(CultureInfo.InvariantCulture, $"Failed login {Math.Min(record.FailedCount, threshold)}/{threshold}");
            if (throttled)
            {
                message += " (repeated within the minimum interval, counted once)";
            }

            if (!duplicate)
            {
                var entry = AddActivity(ActivityType.FailedLogin, ip, country, evt.Source, userName, message, now);
                attempts.Failures.Add(new RecentFailure(eventTime, evt.SourceId, evt.Source, entry, Counted: !throttled));
            }

            if (reason is not null)
            {
                if (!settings.ProtectionEnabled)
                {
                    AddActivity(ActivityType.Ignored, ip, country, evt.Source, userName, $"Would have been banned ({reason}), but protection is paused.", now);
                }
                else
                {
                    banned = ApplyBan(record, reason, null, manual: false, userName, evt.Source, evt.LogText, now);
                }
            }

            db.SaveRecord(record);
        }

        if (banned is not null)
        {
            RaiseBanned(banned);
        }
    }

    /// <summary>Bans an address by hand. A null duration uses the escalation policy; <see cref="TimeSpan.Zero"/> is permanent.</summary>
    public bool BanManually(string ipText, TimeSpan? duration, string? reason)
    {
        if (!IPUtility.TryParseAddress(ipText, out var address))
        {
            throw new ArgumentException($"'{ipText}' is not a valid IP address.");
        }

        var ip = address.ToString();
        var ctx = context;
        if (ctx.IsWhitelisted(address, ip))
        {
            throw new InvalidOperationException($"{ip} is whitelisted. Remove it from the whitelist first.");
        }

        var now = time.GetUtcNow();
        BanEventArgs args;
        lock (sync)
        {
            var record = db.GetRecord(ip) ?? new IPRecord { IPAddress = ip, LastActivityUtc = now };
            record.Country ??= countryLookup(ip);
            record.LastActivityUtc = now;
            args = ApplyBan(record, string.IsNullOrWhiteSpace(reason) ? "Banned manually" : reason.Trim(), duration, manual: true, null, "Manual", null, now,
                changeExistingBan: record.IsBanned);
            db.SaveRecord(record);
        }

        RaiseBanned(args);
        return true;
    }

    /// <summary>Lifts bans. Returns the number of addresses that were unbanned.</summary>
    public int Unban(IEnumerable<string> addresses, string reason)
    {
        var now = time.GetUtcNow();
        var unbanned = new List<IPRecord>();
        lock (sync)
        {
            foreach (var text in addresses)
            {
                var ip = IPUtility.NormalizeText(text);
                if (ip is null)
                {
                    continue;
                }

                var record = db.GetRecord(ip);
                if (record is null)
                {
                    continue;
                }

                bool wasBanned = record.IsBanned;
                LiftBan(record, resetCount: true, now);
                db.SaveRecord(record);
                if (wasBanned)
                {
                    unbanned.Add(record);
                    AddActivity(ActivityType.Unbanned, ip, record.Country, record.Source, null, reason, now);
                }
            }
        }

        foreach (var record in unbanned)
        {
            AddressUnbanned?.Invoke(record, reason);
        }

        if (unbanned.Count > 0)
        {
            BansChanged?.Invoke();
        }

        return unbanned.Count;
    }

    /// <summary>Forgets an address entirely (counters, history and ban).</summary>
    public void Forget(string ipText)
    {
        var ip = IPUtility.NormalizeText(ipText);
        if (ip is null)
        {
            return;
        }

        bool wasBanned;
        lock (sync)
        {
            wasBanned = db.GetRecord(ip)?.IsBanned == true;
            db.DeleteRecord(ip);
        }

        if (wasBanned)
        {
            BansChanged?.Invoke();
        }
    }

    /// <summary>Unbans expired addresses and forgets quiet ones. Returns the number of expired bans.</summary>
    public int RunHousekeeping()
    {
        var now = time.GetUtcNow();
        var policy = context.Settings.BanPolicy;
        var expired = new List<IPRecord>();
        lock (sync)
        {
            foreach (var record in db.GetExpiredBans(now))
            {
                LiftBan(record, policy.ResetFailedAttemptsAfterUnban, now);
                record.LastActivityUtc = now;
                db.SaveRecord(record);
                expired.Add(record);
                AddActivity(ActivityType.Unbanned, record.IPAddress, record.Country, record.Source, null, "Ban expired", now);
            }

            db.ForgetQuietAddresses(now - policy.FailedAttemptWindow, now - policy.RepeatOffenderMemory);
            PruneRecentAttempts(now);
        }

        foreach (var record in expired)
        {
            AddressUnbanned?.Invoke(record, "Ban expired");
        }

        if (expired.Count > 0)
        {
            BansChanged?.Invoke();
        }

        return expired.Count;
    }

    public int ClearAllBans()
    {
        int count;
        lock (sync)
        {
            count = db.ClearAllBans();
        }

        if (count > 0)
        {
            AddActivity(ActivityType.Info, null, null, null, null,
                string.Create(CultureInfo.InvariantCulture, $"All {count} bans were cleared."), time.GetUtcNow());
            BansChanged?.Invoke();
        }

        return count;
    }

    /// <summary>Records an informational entry in the activity feed.</summary>
    public void Log(ActivityType type, string message, string? ip = null) =>
        AddActivity(type, ip, ip is null ? null : countryLookup(ip), null, null, message, time.GetUtcNow());

    private void HandleSuccess(LoginEvent evt, string ip, string? userName, string? country, DateTimeOffset eventTime, DateTimeOffset now)
    {
        List<long> removed = [];
        lock (sync)
        {
            var attempts = GetRecentAttempts(ip, eventTime);

            // One sign-in can produce several success events (an administrator's standard and elevated token).
            if (attempts.LastSuccessUtc is { } lastSuccess && (eventTime - lastSuccess).Duration() <= DuplicateSuccessWindow &&
                string.Equals(attempts.LastSuccessUser ?? string.Empty, userName ?? string.Empty, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(attempts.LastSuccessSource, evt.Source, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            attempts.LastSuccessUtc = eventTime;
            attempts.LastSuccessUser = userName;
            attempts.LastSuccessSource = evt.Source;

            var record = db.GetRecord(ip);
            if (record is not { IsBanned: true })
            {
                // Failed steps right before this sign-in were the client negotiating credentials, not an attack.
                var handshake = attempts.Failures
                    .Where(f => string.Equals(f.Source, evt.Source, StringComparison.OrdinalIgnoreCase) &&
                                eventTime - f.Time <= SignInHandshakeWindow && f.Time - eventTime <= TimeSpan.FromSeconds(2))
                    .ToList();
                if (handshake.Count > 0)
                {
                    foreach (var failure in handshake)
                    {
                        attempts.Failures.Remove(failure);
                        if (failure.Entry.Id > 0)
                        {
                            removed.Add(failure.Entry.Id);
                        }
                    }

                    int counted = handshake.Count(f => f.Counted);
                    if (record is not null && counted > 0)
                    {
                        record.FailedCount = Math.Max(0, record.FailedCount - counted);
                        if (record.FailedCount == 0)
                        {
                            record.FirstFailedUtc = null;
                        }

                        db.SaveRecord(record);
                    }

                    TryDeleteActivity(removed);
                }
            }

            if (context.Settings.BanPolicy.ClearFailedAttemptsOnSuccessfulLogin)
            {
                record = db.GetRecord(ip);
                if (record is { IsBanned: false, FailedCount: > 0 })
                {
                    record.FailedCount = 0;
                    record.FirstFailedUtc = null;
                    record.LastActivityUtc = now;
                    db.SaveRecord(record);
                }
            }
        }

        if (removed.Count > 0)
        {
            try
            {
                ActivityRemoved?.Invoke(removed);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Activity listener failed");
            }
        }

        AddActivity(ActivityType.SuccessfulLogin, ip, country, evt.Source, userName, "Successful sign-in", now);
        SuccessfulLogin?.Invoke(evt with { UserName = userName });
    }

    private void RecordIgnoredFailure(LoginEvent evt, string ip, string? country, string? userName, DateTimeOffset eventTime, DateTimeOffset now, string message)
    {
        lock (sync)
        {
            var attempts = GetRecentAttempts(ip, eventTime);
            if (IsPartOfRecentSignIn(attempts, evt, eventTime))
            {
                return;
            }

            var sameAttempt = FindSameAttempt(attempts, evt, eventTime);
            if (sameAttempt is not null)
            {
                sameAttempt.MergedSources.Add(evt.SourceId);
                MergeUserName(sameAttempt.Entry, userName);
                return;
            }

            var entry = AddActivity(ActivityType.Ignored, ip, country, evt.Source, userName, message, now);
            attempts.Failures.Add(new RecentFailure(eventTime, evt.SourceId, evt.Source, entry, Counted: false));
        }
    }

    private RecentAttempts GetRecentAttempts(string ip, DateTimeOffset eventTime)
    {
        if (!recent.TryGetValue(ip, out var attempts))
        {
            attempts = new RecentAttempts();
            recent[ip] = attempts;
        }

        attempts.Failures.RemoveAll(f => (eventTime - f.Time).Duration() > TimeSpan.FromMinutes(1));
        return attempts;
    }

    /// <summary>
    /// True when a failure happened just before a sign-in from the same address that was already processed
    /// (logs are delivered separately, so the failed step can arrive after the success).
    /// </summary>
    private static bool IsPartOfRecentSignIn(RecentAttempts attempts, LoginEvent evt, DateTimeOffset eventTime) =>
        attempts.LastSuccessUtc is { } success &&
        string.Equals(attempts.LastSuccessSource, evt.Source, StringComparison.OrdinalIgnoreCase) &&
        success - eventTime <= SignInHandshakeWindow && eventTime - success <= TimeSpan.FromSeconds(2);

    /// <summary>A failure from another log, for the same address, that this event is a second report of.</summary>
    private static RecentFailure? FindSameAttempt(RecentAttempts attempts, LoginEvent evt, DateTimeOffset eventTime)
    {
        for (int i = attempts.Failures.Count - 1; i >= 0; i--)
        {
            var failure = attempts.Failures[i];
            if (!string.Equals(failure.SourceId, evt.SourceId, StringComparison.OrdinalIgnoreCase) &&
                !failure.MergedSources.Contains(evt.SourceId) &&
                string.Equals(failure.Source, evt.Source, StringComparison.OrdinalIgnoreCase) &&
                (eventTime - failure.Time).Duration() <= SameAttemptWindow)
            {
                return failure;
            }
        }

        return null;
    }

    private void MergeUserName(ActivityEntry entry, string? userName)
    {
        if (userName is null || !string.IsNullOrEmpty(entry.UserName) || entry.Id <= 0)
        {
            return;
        }

        entry.UserName = userName;
        try
        {
            db.UpdateActivityUserName(entry.Id, userName);
            ActivityUpdated?.Invoke(entry);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to update activity entry");
        }
    }

    private void TryDeleteActivity(IReadOnlyCollection<long> ids)
    {
        if (ids.Count == 0)
        {
            return;
        }

        try
        {
            db.DeleteActivity(ids);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to remove activity entries");
        }
    }

    /// <summary>Forgets correlation state that is too old to matter.</summary>
    private void PruneRecentAttempts(DateTimeOffset now)
    {
        foreach (var (ip, attempts) in recent.ToList())
        {
            attempts.Failures.RemoveAll(f => now - f.Time > TimeSpan.FromMinutes(1));
            if (attempts.Failures.Count == 0 && (attempts.LastSuccessUtc is null || now - attempts.LastSuccessUtc > TimeSpan.FromMinutes(1)))
            {
                recent.Remove(ip);
            }
        }
    }

    private sealed class RecentAttempts
    {
        public List<RecentFailure> Failures { get; } = [];

        public DateTimeOffset? LastSuccessUtc { get; set; }

        public string? LastSuccessUser { get; set; }

        public string? LastSuccessSource { get; set; }
    }

    private sealed record RecentFailure(DateTimeOffset Time, string SourceId, string Source, ActivityEntry Entry, bool Counted)
    {
        public HashSet<string> MergedSources { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private BanEventArgs ApplyBan(IPRecord record, string reason, TimeSpan? duration, bool manual, string? userName, string? source,
        string? logText, DateTimeOffset now, bool changeExistingBan = false)
    {
        var durations = context.Settings.BanPolicy.BanDurations;
        if (durations.Count == 0)
        {
            durations = [TimeSpan.FromDays(1)];
        }

        if (!changeExistingBan || record.BanLevel < 1)
        {
            record.BanLevel = Math.Max(0, record.BanLevel) + 1;
        }

        var effective = duration ?? durations[Math.Min(record.BanLevel - 1, durations.Count - 1)];
        record.IsBanned = true;
        record.BanStartUtc = now;
        record.BanEndUtc = effective <= TimeSpan.Zero ? null : now + effective;
        record.BanReason = reason;
        record.Manual = manual;
        if (!changeExistingBan)
        {
            db.IncrementTotalBans();
        }

        var level = record.BanLevel > 1 && !changeExistingBan ? string.Create(CultureInfo.InvariantCulture, $" (ban #{record.BanLevel})") : string.Empty;
        var what = effective <= TimeSpan.Zero ? (changeExistingBan ? "Ban changed to forever" : "Banned forever") : (changeExistingBan ? "Ban changed to " : "Banned for ") +
            (effective <= TimeSpan.Zero ? string.Empty : TimeFormat.Duration(effective));
        AddActivity(ActivityType.Banned, record.IPAddress, record.Country, source ?? record.Source, userName, $"{what}{level}: {reason}", now);
        logger.LogInformation("Banned {IP} ({Reason})", record.IPAddress, reason);
        return new BanEventArgs(record, reason, effective <= TimeSpan.Zero ? null : effective, userName, source, logText);
    }

    private void RaiseBanned(BanEventArgs args)
    {
        AddressBanned?.Invoke(args);
        BansChanged?.Invoke();
    }

    private static void LiftBan(IPRecord record, bool resetCount, DateTimeOffset now)
    {
        record.IsBanned = false;
        record.BanStartUtc = null;
        record.BanEndUtc = null;
        record.Manual = false;
        if (resetCount)
        {
            record.FailedCount = 0;
            record.FirstFailedUtc = null;
        }

        record.LastActivityUtc = now;
    }

    private void ReleaseWhitelistedBans()
    {
        var ctx = context;
        if (ctx.Whitelist.Count == 0 && ctx.WhitelistRegex is null)
        {
            return;
        }

        var toRelease = db.GetBannedAddresses()
            .Where(ip => IPAddress.TryParse(ip, out var a) && ctx.IsWhitelisted(a, ip))
            .ToList();
        if (toRelease.Count > 0)
        {
            Unban(toRelease, "Address was added to the whitelist");
        }
    }

    private ActivityEntry AddActivity(ActivityType type, string? ip, string? country, string? source, string? userName, string message, DateTimeOffset now)
    {
        var entry = new ActivityEntry
        {
            TimeUtc = now,
            Type = type,
            IPAddress = ip,
            Country = country,
            Source = source,
            UserName = userName,
            Message = message,
        };

        try
        {
            db.AddActivity(entry);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to store activity entry");
        }

        try
        {
            ActivityAdded?.Invoke(entry);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Activity listener failed");
        }

        return entry;
    }
}
