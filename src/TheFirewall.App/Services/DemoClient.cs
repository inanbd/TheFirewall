using System.Windows.Threading;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Feeds;
using TheFirewall.Core.Geo;
using TheFirewall.Core.Ipc;
using TheFirewall.Core.Monitoring;
using TheFirewall.Core.Service;

namespace TheFirewall.App.Services;

/// <summary>
/// Simulated service used with --demo: lets people explore the UI (and lets CI render screenshots)
/// without installing the Windows service. All data is made up.
/// </summary>
public sealed class DemoClient : IFirewallClient
{
    private static readonly string[] CountryPool = ["CN", "RU", "US", "BR", "IN", "VN", "NL", "DE", "KR", "ID", "IR", "UA", "TR", "FR", "SG"];
    private static readonly string[] UserPool = ["administrator", "admin", "user", "test", "sa", "guest", "backup", "scanner", "sqladmin", "support", "root", "office"];
    private static readonly (string Source, int Weight)[] SourcePool = [("RDP", 60), ("MSSQL", 15), ("SSH", 12), ("MSExchange", 6), ("FTP", 4), ("RDWeb", 3)];

    private readonly Dispatcher dispatcher;
    private readonly Random random;
    private readonly List<ActivityEntry> activity = [];
    private readonly Dictionary<string, IPRecord> records = new(StringComparer.OrdinalIgnoreCase);
    private readonly DateTimeOffset started = DateTimeOffset.UtcNow.AddDays(-3).AddHours(-4);
    private readonly bool live;
    private FirewallSettings settings;
    private DispatcherTimer? timer;
    private long nextId = 1;
    private long totalBans = 1873;

    public DemoClient(Dispatcher dispatcher, bool live = true, int seed = 42)
    {
        this.dispatcher = dispatcher;
        this.live = live;
        random = new Random(seed);
        settings = CreateSettings();
        Seed();
    }

    public bool IsConnected => true;

    public bool CanMakeChanges => true;

    public string? ServiceVersion => "1.0.0 (demo)";

    public ServiceStatusDto? LastStatus { get; private set; }

    public bool IsDemo => true;

    public event EventHandler? ConnectionChanged;

    public event EventHandler<ActivityEntry>? ActivityReceived;

    public event EventHandler<ServiceStatusDto>? StatusReceived;

    // The simulation never edits or removes entries.
    public event EventHandler<ActivityEntry>? ActivityUpdated
    {
        add { }
        remove { }
    }

    public event EventHandler<IReadOnlyList<long>>? ActivityRemoved
    {
        add { }
        remove { }
    }

    public void Start()
    {
        LastStatus = BuildStatus();
        dispatcher.InvokeAsync(() =>
        {
            ConnectionChanged?.Invoke(this, EventArgs.Empty);
            StatusReceived?.Invoke(this, LastStatus);
        });

        if (live)
        {
            timer = new DispatcherTimer(DispatcherPriority.Background, dispatcher) { Interval = TimeSpan.FromSeconds(2.5) };
            timer.Tick += (_, _) => SimulateAttack();
            timer.Start();
        }
    }

    public Task StopAsync()
    {
        timer?.Stop();
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------ Simulation

    private static FirewallSettings CreateSettings()
    {
        var s = new FirewallSettings();
        s.Whitelist.Add(new AddressEntry { Value = "203.0.113.0/24", Comment = "Head office", AddedUtc = DateTimeOffset.UtcNow.AddDays(-40) });
        s.Whitelist.Add(new AddressEntry { Value = "198.51.100.17", Comment = "Monitoring (uptime checks)", AddedUtc = DateTimeOffset.UtcNow.AddDays(-12) });
        s.Blacklist.Add(new AddressEntry { Value = "45.141.84.0/24", Comment = "Known RDP brute-force network", AddedUtc = DateTimeOffset.UtcNow.AddDays(-5) });
        s.CustomRules.Add(new CustomFirewallRule
        {
            Id = "demo-rdp",
            Name = "Remote Desktop from office only",
            Description = "Only the office network may reach RDP.",
            Action = RuleAction.Allow,
            Protocol = RuleProtocol.Tcp,
            LocalPorts = "3389",
            RemoteAddresses = "203.0.113.0/24",
        });
        s.CustomRules.Add(new CustomFirewallRule
        {
            Id = "demo-smb",
            Name = "Block SMB from the internet",
            Action = RuleAction.Block,
            Protocol = RuleProtocol.Tcp,
            LocalPorts = "445",
            RemoteAddresses = "Internet",
        });
        s.CustomRules.Add(new CustomFirewallRule
        {
            Id = "demo-telnet",
            Name = "Block outbound Telnet",
            Enabled = false,
            Action = RuleAction.Block,
            Direction = RuleDirection.Outbound,
            Protocol = RuleProtocol.Tcp,
            RemotePorts = "23",
        });
        s.UserNames.InstantBanUserNames = ["root", "test", "guest"];
        s.CountryBlocking.Countries = ["KP", "RU"];
        s.ThreatFeeds[0].Enabled = true;
        return s;
    }

    private void Seed()
    {
        var now = DateTimeOffset.UtcNow;

        // Three days of history with a busier night.
        for (int i = 0; i < 900; i++)
        {
            var minutesAgo = Math.Pow(random.NextDouble(), 1.6) * 60 * 24 * 3;
            var time = now.AddMinutes(-minutesAgo);
            var ip = RandomIp();
            AddActivityInternal(new ActivityEntry
            {
                TimeUtc = time,
                Type = ActivityType.FailedLogin,
                IPAddress = ip,
                Country = CountryOf(ip),
                Source = RandomSource(),
                UserName = UserPool[random.Next(UserPool.Length)],
                Message = $"Failed login {random.Next(1, 6)}/5",
            }, raise: false);
        }

        for (int i = 0; i < 64; i++)
        {
            var ip = RandomIp();
            var bannedAt = now.AddMinutes(-Math.Pow(random.NextDouble(), 1.4) * 60 * 24 * 2);
            var level = random.Next(10) == 0 ? 2 : 1;
            var record = new IPRecord
            {
                IPAddress = ip,
                Country = CountryOf(ip),
                Source = RandomSource(),
                FailedCount = 5 + random.Next(0, 40),
                IsBanned = true,
                BanStartUtc = bannedAt,
                BanEndUtc = random.Next(15) == 0 ? null : bannedAt.AddDays(level == 1 ? 1 : 7),
                BanLevel = level,
                BanReason = "5 failed logins via RDP",
                LastActivityUtc = bannedAt,
                LastFailedUtc = bannedAt,
                FirstFailedUtc = bannedAt.AddMinutes(-random.Next(1, 30)),
            };
            record.AddUserName(UserPool[random.Next(UserPool.Length)]);
            record.AddUserName(UserPool[random.Next(UserPool.Length)]);
            records[ip] = record;
            AddActivityInternal(new ActivityEntry
            {
                TimeUtc = bannedAt,
                Type = ActivityType.Banned,
                IPAddress = ip,
                Country = record.Country,
                Source = record.Source,
                UserName = record.UserNames?.Split(',')[0],
                Message = $"Banned for {(level == 1 ? "1 day" : "7 days")}: 5 failed logins via {record.Source}",
            }, raise: false);
        }

        for (int i = 0; i < 18; i++)
        {
            var ip = RandomIp();
            var last = now.AddMinutes(-random.Next(1, 600));
            var record = new IPRecord
            {
                IPAddress = ip,
                Country = CountryOf(ip),
                Source = RandomSource(),
                FailedCount = random.Next(1, 5),
                LastFailedUtc = last,
                FirstFailedUtc = last.AddMinutes(-random.Next(1, 20)),
                LastActivityUtc = last,
            };
            record.AddUserName(UserPool[random.Next(UserPool.Length)]);
            records[ip] = record;
        }

        AddActivityInternal(new ActivityEntry { TimeUtc = now.AddMinutes(-42), Type = ActivityType.SuccessfulLogin, IPAddress = "203.0.113.24", Country = "US", Source = "RDP", UserName = "alice", Message = "Successful sign-in" }, false);
        AddActivityInternal(new ActivityEntry { TimeUtc = now.AddHours(-3), Type = ActivityType.SuccessfulLogin, IPAddress = "203.0.113.31", Country = "US", Source = "SSH", UserName = "deploy", Message = "Successful sign-in" }, false);
        AddActivityInternal(new ActivityEntry { TimeUtc = now.AddHours(-5), Type = ActivityType.Ignored, IPAddress = "192.168.1.40", Source = "RDP", UserName = "bob", Message = "Failed login from a local network address (not counted)." }, false);
        activity.Sort((a, b) => b.TimeUtc.CompareTo(a.TimeUtc));
    }

    private void SimulateAttack()
    {
        var now = DateTimeOffset.UtcNow;
        string ip;
        IPRecord? record = records.Values.Where(r => !r.IsBanned && r.FailedCount > 0).OrderBy(_ => random.Next()).FirstOrDefault();
        if (record is null || random.Next(3) == 0)
        {
            ip = RandomIp();
            record = new IPRecord { IPAddress = ip, Country = CountryOf(ip), Source = RandomSource(), LastActivityUtc = now };
            records[ip] = record;
        }

        ip = record.IPAddress;
        var user = UserPool[random.Next(UserPool.Length)];
        record.FailedCount++;
        record.LastFailedUtc = now;
        record.FirstFailedUtc ??= now;
        record.AddUserName(user);
        AddActivityInternal(new ActivityEntry
        {
            TimeUtc = now,
            Type = ActivityType.FailedLogin,
            IPAddress = ip,
            Country = record.Country,
            Source = record.Source,
            UserName = user,
            Message = $"Failed login {Math.Min(record.FailedCount, 5)}/5",
        }, raise: true);

        if (record.FailedCount >= 5)
        {
            Ban(record, $"5 failed logins via {record.Source}", TimeSpan.FromDays(1), user);
        }
    }

    private void Ban(IPRecord record, string reason, TimeSpan? duration, string? user)
    {
        var now = DateTimeOffset.UtcNow;
        record.IsBanned = true;
        record.BanLevel++;
        record.BanStartUtc = now;
        record.BanEndUtc = duration is { } d && d > TimeSpan.Zero ? now + d : null;
        record.BanReason = reason;
        totalBans++;
        AddActivityInternal(new ActivityEntry
        {
            TimeUtc = now,
            Type = ActivityType.Banned,
            IPAddress = record.IPAddress,
            Country = record.Country,
            Source = record.Source,
            UserName = user,
            Message = $"Banned {(record.BanEndUtc is null ? "permanently" : "for " + Core.Engine.TimeFormat.Duration(duration))}: {reason}",
        }, raise: true);
        PushStatus();
    }

    private void AddActivityInternal(ActivityEntry entry, bool raise)
    {
        entry.Id = nextId++;
        activity.Insert(0, entry);
        if (activity.Count > 5000)
        {
            activity.RemoveAt(activity.Count - 1);
        }

        if (raise)
        {
            ActivityReceived?.Invoke(this, entry);
        }
    }

    private void PushStatus()
    {
        LastStatus = BuildStatus();
        StatusReceived?.Invoke(this, LastStatus);
    }

    private string RandomIp()
    {
        int a;
        do
        {
            a = random.Next(1, 223);
        }
        while (a is 10 or 127 or 172 or 192 or 100 or 169 or 203 or 198);

        return $"{a}.{random.Next(0, 256)}.{random.Next(0, 256)}.{random.Next(1, 255)}";
    }

    private string CountryOf(string ip)
    {
        var hash = ip.Aggregate(17, (h, c) => (h * 31) + c);
        var weighted = Math.Abs(hash % 100);
        return weighted < 34 ? "CN" : weighted < 50 ? "RU" : weighted < 60 ? "US" : CountryPool[Math.Abs(hash / 7) % CountryPool.Length];
    }

    private string RandomSource()
    {
        int total = SourcePool.Sum(s => s.Weight);
        int pick = random.Next(total);
        foreach (var (source, weight) in SourcePool)
        {
            if (pick < weight)
            {
                return source;
            }

            pick -= weight;
        }

        return "RDP";
    }

    private ServiceStatusDto BuildStatus() => new()
    {
        Version = "1.0.0",
        MachineName = "DEMO-SERVER",
        StartedUtc = started,
        ProtectionEnabled = settings.ProtectionEnabled,
        ActiveBans = records.Values.Count(r => r.IsBanned),
        FirewallName = "Windows Defender Firewall",
        FirewallRuleCount = 9,
        BlockedEntryCount = records.Values.Count(r => r.IsBanned) + 1 + 4_812,
        LastFirewallSyncUtc = DateTimeOffset.UtcNow.AddSeconds(-20),
        GeoDatabaseAvailable = true,
        GeoDatabaseVersion = DateTimeOffset.UtcNow.ToString("yyyy-MM"),
        ActiveSources = 6,
        DataDirectory = @"C:\ProgramData\TheFirewall",
        Warnings = settings.ProtectionEnabled ? [] : ["Protection is paused. Failed logins are recorded but nothing is banned."],
    };

    // ------------------------------------------------------------------ IFirewallClient

    public Task<ServiceStatusDto> GetStatusAsync() => Task.FromResult(LastStatus = BuildStatus());

    public Task<DashboardStats> GetStatsAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var dayAgo = now.AddDays(-1);
        var stats = new DashboardStats
        {
            FailedLast24h = activity.Count(a => a.Type == ActivityType.FailedLogin && a.TimeUtc >= dayAgo),
            BansLast24h = activity.Count(a => a.Type == ActivityType.Banned && a.TimeUtc >= dayAgo),
            SuccessfulLast24h = activity.Count(a => a.Type == ActivityType.SuccessfulLogin && a.TimeUtc >= dayAgo),
            ActiveBans = records.Values.Count(r => r.IsBanned),
            WatchedAddresses = records.Values.Count(r => !r.IsBanned && r.FailedCount > 0),
            TotalBansAllTime = totalBans,
        };

        var hourStart = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 0, 0, TimeSpan.Zero).AddHours(-23);
        for (int h = 0; h < 24; h++)
        {
            var from = hourStart.AddHours(h);
            var to = from.AddHours(1);
            stats.HourlyFailed.Add(activity.Count(a => a.Type == ActivityType.FailedLogin && a.TimeUtc >= from && a.TimeUtc < to));
            stats.HourlyBans.Add(activity.Count(a => a.Type == ActivityType.Banned && a.TimeUtc >= from && a.TimeUtc < to));
        }

        var dayStart = new DateTimeOffset(now.Year, now.Month, now.Day, 0, 0, 0, TimeSpan.Zero).AddDays(-29);
        for (int d = 0; d < 30; d++)
        {
            var from = dayStart.AddDays(d);
            stats.DailyFailed.Add(activity.Count(a => a.Type == ActivityType.FailedLogin && a.TimeUtc >= from && a.TimeUtc < from.AddDays(1)));
        }

        var recent = activity.Where(a => a.Type == ActivityType.FailedLogin && a.TimeUtc >= dayAgo).ToList();
        stats.TopCountries = Top(recent.Select(a => a.Country));
        stats.TopSources = Top(recent.Select(a => a.Source));
        stats.TopUserNames = Top(recent.Select(a => a.UserName));
        stats.TopAddresses = Top(recent.Select(a => a.IPAddress));
        return Task.FromResult(stats);

        static List<NamedCount> Top(IEnumerable<string?> values) => values.Where(v => !string.IsNullOrEmpty(v))
            .GroupBy(v => v!).Select(g => new NamedCount { Name = g.Key, Count = g.Count() }).OrderByDescending(n => n.Count).Take(8).ToList();
    }

    public Task<List<ActivityEntry>> QueryActivityAsync(ActivityQuery query)
    {
        IEnumerable<ActivityEntry> result = activity;
        if (query.SinceUtc is { } since)
        {
            result = result.Where(a => a.TimeUtc >= since);
        }

        if (query.BeforeId is { } before)
        {
            result = result.Where(a => a.Id < before);
        }

        if (query.Types is { Count: > 0 } types)
        {
            result = result.Where(a => types.Contains(a.Type));
        }

        if (!string.IsNullOrWhiteSpace(query.IPAddress))
        {
            result = result.Where(a => a.IPAddress == query.IPAddress);
        }

        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            var s = query.Search.Trim();
            result = result.Where(a => (a.IPAddress?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                       (a.UserName?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                       (a.Source?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                       (a.Message?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        return Task.FromResult(result.Take(query.Limit).ToList());
    }

    public Task<List<IPRecord>> GetBansAsync() => Task.FromResult(records.Values.Where(r => r.IsBanned).OrderByDescending(r => r.BanStartUtc).ToList());

    public Task<List<IPRecord>> GetWatchedAsync(int limit = 1000) =>
        Task.FromResult(records.Values.Where(r => !r.IsBanned && r.FailedCount > 0).OrderByDescending(r => r.LastFailedUtc).Take(limit).ToList());

    public Task BanAsync(BanRequest request)
    {
        var ip = Core.Networking.IPUtility.NormalizeText(request.IPAddress) ?? throw new IpcException($"'{request.IPAddress}' is not a valid IP address.");
        if (!records.TryGetValue(ip, out var record))
        {
            record = new IPRecord { IPAddress = ip, Country = CountryOf(ip), Source = "Manual", LastActivityUtc = DateTimeOffset.UtcNow };
            records[ip] = record;
        }

        TimeSpan? duration = request.DurationMinutes switch { null => TimeSpan.FromDays(1), 0 => null, var m => TimeSpan.FromMinutes(m.Value) };
        Ban(record, string.IsNullOrWhiteSpace(request.Reason) ? "Banned manually" : request.Reason!, duration, null);
        record.Manual = true;
        return Task.CompletedTask;
    }

    public Task<int> UnbanAsync(UnbanRequest request)
    {
        int count = 0;
        foreach (var ip in request.IPAddresses)
        {
            if (records.TryGetValue(ip, out var record) && record.IsBanned)
            {
                record.IsBanned = false;
                record.FailedCount = 0;
                record.BanEndUtc = null;
                count++;
                AddActivityInternal(new ActivityEntry { TimeUtc = DateTimeOffset.UtcNow, Type = ActivityType.Unbanned, IPAddress = ip, Country = record.Country, Message = "Unbanned manually" }, true);
            }

            if (request.AddToWhitelist)
            {
                settings.Whitelist.Add(new AddressEntry { Value = ip, Comment = request.Comment ?? "Added from the ban list" });
            }
        }

        PushStatus();
        return Task.FromResult(count);
    }

    public Task<int> ClearBansAsync()
    {
        var banned = records.Values.Where(r => r.IsBanned).Select(r => r.IPAddress).ToList();
        return UnbanAsync(new UnbanRequest { IPAddresses = banned });
    }

    public Task<int> ImportBansAsync(ImportBansRequest request)
    {
        foreach (var record in request.Bans.Where(b => b.IsBanned))
        {
            records[record.IPAddress] = record;
        }

        PushStatus();
        return Task.FromResult(request.Bans.Count);
    }

    public Task<LookupResult> LookupAsync(string ip)
    {
        records.TryGetValue(ip, out var record);
        return Task.FromResult(new LookupResult
        {
            IPAddress = ip,
            Country = record?.Country ?? CountryOf(ip),
            Record = record,
            IsWhitelisted = settings.Whitelist.Any(w => w.Value == ip),
            RecentActivity = activity.Where(a => a.IPAddress == ip).Take(50).ToList(),
        });
    }

    public Task<FirewallSettings> GetSettingsAsync() => Task.FromResult(SettingsStore.Clone(settings));

    public Task<SaveSettingsResponse> SaveSettingsAsync(FirewallSettings newSettings)
    {
        SettingsStore.Normalize(newSettings);
        var errors = SettingsStore.Validate(newSettings);
        if (errors.Count > 0)
        {
            return Task.FromResult(new SaveSettingsResponse { Errors = errors });
        }

        bool protectionChanged = settings.ProtectionEnabled != newSettings.ProtectionEnabled;
        settings = SettingsStore.Clone(newSettings);
        if (protectionChanged)
        {
            AddActivityInternal(new ActivityEntry { TimeUtc = DateTimeOffset.UtcNow, Type = ActivityType.Info, Message = settings.ProtectionEnabled ? "Protection resumed." : "Protection paused." }, true);
        }

        PushStatus();
        return Task.FromResult(new SaveSettingsResponse { Saved = true });
    }

    public async Task<ServiceStatusDto> SetProtectionAsync(bool enabled)
    {
        var copy = SettingsStore.Clone(settings);
        copy.ProtectionEnabled = enabled;
        await SaveSettingsAsync(copy);
        return LastStatus!;
    }

    public Task<List<SourceInfoDto>> GetSourcesAsync()
    {
        var active = new HashSet<string>(["rdp-logon", "rdp-rdpcorets", "mssql", "ssh-openssh", "rdp-success", "ssh-success", "custom-eventlog", "custom-logfile", "exchange-protocol", "iis-ftp", "rdweb"]);
        var list = SourceCatalog.GetEffective(settings).Select(def => new SourceInfoDto
        {
            Definition = def,
            IsBuiltIn = def.IsBuiltIn,
            Status = new SourceStatus
            {
                SourceId = def.Id,
                State = !def.Enabled ? SourceState.Disabled : active.Contains(def.Id) ? SourceState.Active : SourceState.NotDetected,
                Message = def.Enabled && !active.Contains(def.Id) ? (def.Kind == LogSourceKind.EventLog ? $"The event log '{def.LogName}' does not exist on this computer." : "Log folder not found on this computer.") : null,
                EventsDetected = active.Contains(def.Id) ? random.Next(0, 4000) : 0,
                LastEventUtc = active.Contains(def.Id) ? DateTimeOffset.UtcNow.AddMinutes(-random.Next(1, 300)) : null,
            },
        }).ToList();
        return Task.FromResult(list);
    }

    public Task<SourceTestResult> TestSourceAsync(SourceTestRequest request) => Task.FromResult(FirewallCoordinator.TestSource(request));

    public Task<List<CountryDto>> GetCountriesAsync() =>
        Task.FromResult(Countries.All.Select(c => new CountryDto { Code = c.Code, Name = c.Name, Region = c.Region, RangeCount = ((c.Code[0] * 37) + (c.Code[1] * 11)) % 3000 + 5 }).ToList());

    public Task<ServiceStatusDto> UpdateGeoAsync() => GetStatusAsync();

    public Task<List<FeedInfoDto>> GetFeedsAsync() => Task.FromResult(settings.ThreatFeeds.Select(f => new FeedInfoDto
    {
        Feed = f,
        Status = new ThreatFeedStatus
        {
            FeedId = f.Id,
            EntryCount = f.Enabled ? 1_482 : 0,
            LastUpdatedUtc = f.Enabled ? DateTimeOffset.UtcNow.AddHours(-2) : null,
        },
    }).ToList());

    public Task<List<FeedInfoDto>> RefreshFeedsAsync() => GetFeedsAsync();
}
