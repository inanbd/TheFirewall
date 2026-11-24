using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Engine;
using TheFirewall.Core.Monitoring;

namespace TheFirewall.Core.Tests;

public sealed class BanEngineTests : IDisposable
{
    private readonly TempDirectory dir = new();
    private readonly FirewallDatabase db;
    private readonly ManualTimeProvider time = new(new DateTimeOffset(2026, 11, 20, 12, 0, 0, TimeSpan.Zero));
    private readonly FirewallSettings settings = new();
    private readonly List<ActivityEntry> activity = [];
    private int bansChanged;

    public BanEngineTests()
    {
        db = new FirewallDatabase(dir.File("test.db"));
        settings.BanPolicy.FailedAttemptsBeforeBan = 3;
        settings.BanPolicy.MinimumTimeBetweenFailedAttempts = TimeSpan.Zero;
        settings.BanPolicy.BanDurations = [TimeSpan.FromHours(1), TimeSpan.FromDays(1), TimeSpan.Zero];
    }

    private BanEngine CreateEngine()
    {
        var engine = new BanEngine(db, settings, Log.Null, time, ip => ip.StartsWith("203.", StringComparison.Ordinal) ? "ZZ" : "US");
        engine.ActivityAdded += activity.Add;
        engine.BansChanged += () => bansChanged++;
        return engine;
    }

    private LoginEvent Failed(string ip, string? user = "admin", int threshold = 0) => new()
    {
        IPAddress = ip,
        UserName = user,
        Source = "RDP",
        Timestamp = time.GetUtcNow(),
        FailedAttemptsBeforeBan = threshold,
    };

    [Fact]
    public void Bans_after_threshold()
    {
        var engine = CreateEngine();
        engine.Process(Failed("198.51.100.10"));
        engine.Process(Failed("198.51.100.10"));
        Assert.False(db.GetRecord("198.51.100.10")!.IsBanned);

        engine.Process(Failed("198.51.100.10"));
        var record = db.GetRecord("198.51.100.10")!;
        Assert.True(record.IsBanned);
        Assert.Equal(1, record.BanLevel);
        Assert.Equal(time.Now + TimeSpan.FromHours(1), record.BanEndUtc);
        Assert.Equal(1, bansChanged);
        Assert.Contains(activity, a => a.Type == ActivityType.Banned && a.IPAddress == "198.51.100.10");
        Assert.Equal(["198.51.100.10"], db.GetBannedAddresses());
    }

    [Fact]
    public void Source_threshold_overrides_global()
    {
        var engine = CreateEngine();
        engine.Process(Failed("198.51.100.11", threshold: 1));
        Assert.True(db.GetRecord("198.51.100.11")!.IsBanned);
    }

    [Fact]
    public void Ignores_internal_and_whitelisted_addresses()
    {
        settings.Whitelist.Add(new AddressEntry { Value = "198.51.100.0/24" });
        var engine = CreateEngine();
        for (int i = 0; i < 5; i++)
        {
            engine.Process(Failed("192.168.1.50"));
            engine.Process(Failed("198.51.100.99"));
        }

        Assert.Empty(db.GetBannedAddresses());
        Assert.Null(db.GetRecord("192.168.1.50"));
        Assert.All(activity, a => Assert.Equal(ActivityType.Ignored, a.Type));
    }

    [Fact]
    public void Escalates_ban_durations_for_repeat_offenders()
    {
        var engine = CreateEngine();
        void Attack()
        {
            for (int i = 0; i < 3; i++)
            {
                engine.Process(Failed("203.0.113.66"));
            }
        }

        Attack();
        Assert.Equal(time.Now + TimeSpan.FromHours(1), db.GetRecord("203.0.113.66")!.BanEndUtc);

        time.Advance(TimeSpan.FromHours(2));
        Assert.Equal(1, engine.RunHousekeeping());
        Assert.False(db.GetRecord("203.0.113.66")!.IsBanned);

        Attack();
        var second = db.GetRecord("203.0.113.66")!;
        Assert.Equal(2, second.BanLevel);
        Assert.Equal(time.Now + TimeSpan.FromDays(1), second.BanEndUtc);

        time.Advance(TimeSpan.FromDays(2));
        engine.RunHousekeeping();
        Attack();
        var third = db.GetRecord("203.0.113.66")!;
        Assert.True(third.IsBanned);
        Assert.Null(third.BanEndUtc); // permanent
        Assert.Equal("ZZ", third.Country);
    }

    [Fact]
    public void Failed_attempts_outside_window_are_forgotten()
    {
        settings.BanPolicy.FailedAttemptWindow = TimeSpan.FromMinutes(30);
        var engine = CreateEngine();
        engine.Process(Failed("198.51.100.20"));
        engine.Process(Failed("198.51.100.20"));
        time.Advance(TimeSpan.FromHours(1));
        engine.Process(Failed("198.51.100.20"));
        Assert.Equal(1, db.GetRecord("198.51.100.20")!.FailedCount);
        Assert.False(db.GetRecord("198.51.100.20")!.IsBanned);
    }

    [Fact]
    public void Throttles_attempts_that_arrive_too_fast()
    {
        settings.BanPolicy.MinimumTimeBetweenFailedAttempts = TimeSpan.FromSeconds(5);
        var engine = CreateEngine();
        for (int i = 0; i < 10; i++)
        {
            engine.Process(Failed("198.51.100.21"));
        }

        Assert.Equal(1, db.GetRecord("198.51.100.21")!.FailedCount);
    }

    [Fact]
    public void Instant_ban_user_names()
    {
        settings.UserNames.InstantBanUserNames = ["root", "test"];
        var engine = CreateEngine();
        engine.Process(Failed("198.51.100.30", "ROOT"));
        Assert.True(db.GetRecord("198.51.100.30")!.IsBanned);
    }

    [Fact]
    public void Allowed_user_names_get_a_higher_threshold_and_unknown_can_be_banned_immediately()
    {
        settings.UserNames.AllowedUserNames = ["alice"];
        settings.UserNames.FailedAttemptsBeforeBanForAllowedUserNames = 10;
        settings.UserNames.BanUnknownUserNamesImmediately = true;
        var engine = CreateEngine();

        for (int i = 0; i < 5; i++)
        {
            engine.Process(Failed("198.51.100.40", "alice@contoso.com"));
            engine.Process(Failed("198.51.100.41", "CONTOSO\\alicr")); // typo within edit distance
        }

        Assert.False(db.GetRecord("198.51.100.40")!.IsBanned);
        Assert.False(db.GetRecord("198.51.100.41")!.IsBanned);

        engine.Process(Failed("198.51.100.42", "mallory"));
        Assert.True(db.GetRecord("198.51.100.42")!.IsBanned);
    }

    [Fact]
    public void Paused_protection_records_but_does_not_ban()
    {
        settings.ProtectionEnabled = false;
        var engine = CreateEngine();
        for (int i = 0; i < 5; i++)
        {
            engine.Process(Failed("198.51.100.50"));
        }

        Assert.Empty(db.GetBannedAddresses());
        Assert.Contains(activity, a => a.Type == ActivityType.Ignored && a.Message!.Contains("paused", StringComparison.Ordinal));
    }

    [Fact]
    public void Manual_ban_and_unban()
    {
        var engine = CreateEngine();
        engine.BanManually("198.51.100.60", TimeSpan.Zero, "Scanner");
        var record = db.GetRecord("198.51.100.60")!;
        Assert.True(record.IsBanned);
        Assert.True(record.Manual);
        Assert.Null(record.BanEndUtc);

        Assert.Equal(1, engine.Unban(["198.51.100.60"], "test"));
        Assert.False(db.GetRecord("198.51.100.60")!.IsBanned);
        Assert.Equal(2, bansChanged);
    }

    [Fact]
    public void Whitelisting_a_banned_address_releases_it()
    {
        var engine = CreateEngine();
        engine.BanManually("198.51.100.70", null, null);
        settings.Whitelist.Add(new AddressEntry { Value = "198.51.100.70" });
        engine.UpdateSettings(settings);
        Assert.False(db.GetRecord("198.51.100.70")!.IsBanned);
    }

    [Fact]
    public void Successful_login_can_clear_counter()
    {
        settings.BanPolicy.ClearFailedAttemptsOnSuccessfulLogin = true;
        var engine = CreateEngine();
        engine.Process(Failed("198.51.100.80"));
        engine.Process(Failed("198.51.100.80"));
        engine.Process(Failed("198.51.100.80") with { Kind = LoginEventKind.Successful });
        Assert.Equal(0, db.GetRecord("198.51.100.80")!.FailedCount);
        Assert.Contains(activity, a => a.Type == ActivityType.SuccessfulLogin);
    }

    [Fact]
    public void Dashboard_statistics()
    {
        var engine = CreateEngine();
        for (int i = 0; i < 3; i++)
        {
            engine.Process(Failed("198.51.100.90"));
        }

        var stats = db.GetDashboardStats(time.Now);
        Assert.Equal(3, stats.FailedLast24h);
        Assert.Equal(1, stats.BansLast24h);
        Assert.Equal(1, stats.ActiveBans);
        Assert.Equal(1, stats.TotalBansAllTime);
        Assert.Equal(24, stats.HourlyFailed.Count);
        Assert.Equal(3, stats.HourlyFailed[^1]);
        Assert.Equal("RDP", Assert.Single(stats.TopSources).Name);
        Assert.Equal("US", Assert.Single(stats.TopCountries).Name);
    }

    public void Dispose()
    {
        db.Dispose();
        dir.Dispose();
    }
}
