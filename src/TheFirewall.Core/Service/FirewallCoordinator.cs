using System.Globalization;
using System.Net;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using TheFirewall.Core.Actions;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Engine;
using TheFirewall.Core.Feeds;
using TheFirewall.Core.Firewall;
using TheFirewall.Core.Geo;
using TheFirewall.Core.Ipc;
using TheFirewall.Core.Monitoring;
using TheFirewall.Core.Networking;
using TheFirewall.Core.Ports;

namespace TheFirewall.Core.Service;

/// <summary>
/// The heart of the service: owns settings, storage, the ban engine, log monitors and firewall synchronisation.
/// Platform specific pieces (Windows Firewall, event log) are injected.
/// </summary>
public sealed class FirewallCoordinator : IAsyncDisposable
{
    private readonly FirewallPaths paths;
    private readonly IFirewallBackend backend;
    private readonly IReadOnlyList<Func<Action<LoginEvent>, ILoginMonitor>> monitorFactories;
    private readonly ILoggerFactory loggerFactory;
    private readonly ILogger logger;
    private readonly HttpClient http;
    private readonly TimeProvider time;
    private readonly SettingsStore settingsStore;
    private readonly Channel<LoginEvent> events = Channel.CreateBounded<LoginEvent>(new BoundedChannelOptions(100_000)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
    });

    private readonly Channel<bool> syncRequests = Channel.CreateBounded<bool>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });
    private readonly SemaphoreSlim firewallLock = new(1, 1);
    private readonly SemaphoreSlim settingsLock = new(1, 1);
    private readonly List<ILoginMonitor> monitors = [];
    private readonly List<string> startupWarnings = [];
    private readonly CancellationTokenSource shutdown = new();
    private readonly List<Task> loops = [];

    private FirewallSettings settings = new();
    private FirewallDatabase? db;
    private BanEngine? engine;
    private FirewallSynchronizer? synchronizer;
    private ThreatFeedService? feeds;
    private GeoIpDatabase? geo;
    private string? geoError;
    private ProcessLauncher? launcher;
    private Dictionary<string, List<string>>? lastBanChunks;
    private (string Key, List<IPAddressRange> Ranges)? countryCache;
    private readonly Dictionary<string, List<IPAddressRange>> portCountryCache = new(StringComparer.Ordinal);
    private string? lastPortStateKey;
    private int ruleCount;
    private int blockedEntries;
    private DateTimeOffset? lastSyncUtc;
    private string? firewallError;
    private FirewallProfileState profileState = new();
    private DateTimeOffset nextActivityPrune = DateTimeOffset.MinValue;

    public FirewallCoordinator(FirewallPaths paths, IFirewallBackend backend, IEnumerable<Func<Action<LoginEvent>, ILoginMonitor>> monitorFactories,
        ILoggerFactory loggerFactory, HttpClient http, string version, TimeProvider? time = null)
    {
        this.paths = paths;
        this.backend = backend;
        this.monitorFactories = monitorFactories.ToList();
        this.loggerFactory = loggerFactory;
        this.http = http;
        this.time = time ?? TimeProvider.System;
        Version = version;
        logger = loggerFactory.CreateLogger<FirewallCoordinator>();
        settingsStore = new SettingsStore(paths.SettingsFile, logger);
    }

    public string Version { get; }

    public DateTimeOffset StartedUtc { get; private set; }

    /// <summary>Raised for every new activity entry.</summary>
    public event Action<ActivityEntry>? ActivityPublished;

    /// <summary>Raised when an activity entry changed.</summary>
    public event Action<ActivityEntry>? ActivityChanged;

    /// <summary>Raised when activity entries were removed.</summary>
    public event Action<IReadOnlyList<long>>? ActivityDeleted;

    /// <summary>Raised when the overall status changes (protection toggled, firewall synchronised...).</summary>
    public event Action<ServiceStatusDto>? StatusChanged;

    public FirewallSettings Settings => settings;

    public BanEngine Engine => engine ?? throw new InvalidOperationException("The coordinator has not been started.");

    public FirewallDatabase Database => db ?? throw new InvalidOperationException("The coordinator has not been started.");

    /// <summary>Adds a warning that is shown in the app (e.g. auditing could not be enabled).</summary>
    public void AddStartupWarning(string warning)
    {
        lock (startupWarnings)
        {
            startupWarnings.Add(warning);
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(paths.DataDirectory);
        Directory.CreateDirectory(paths.CustomLogsDirectory);
        StartedUtc = time.GetUtcNow();
        settings = settingsStore.Load();
        db = new FirewallDatabase(paths.DatabaseFile);
        geo = GeoIpUpdater.TryLoadInstalled(paths.GeoDirectory, logger);
        launcher = new ProcessLauncher(loggerFactory.CreateLogger<ProcessLauncher>());
        engine = new BanEngine(db, settings, loggerFactory.CreateLogger<BanEngine>(), time, ip => geo?.Lookup(ip));
        synchronizer = new FirewallSynchronizer(backend, db, loggerFactory.CreateLogger<FirewallSynchronizer>());
        feeds = new ThreatFeedService(paths.FeedsDirectory, http, loggerFactory.CreateLogger<ThreatFeedService>(), time);
        feeds.LoadCache(settings.ThreatFeeds);

        engine.ActivityAdded += entry => ActivityPublished?.Invoke(entry);
        engine.ActivityUpdated += entry => ActivityChanged?.Invoke(entry);
        engine.ActivityRemoved += ids => ActivityDeleted?.Invoke(ids);
        engine.BansChanged += RequestFirewallSync;
        engine.AddressBanned += OnBanned;
        engine.AddressUnbanned += OnUnbanned;
        engine.SuccessfulLogin += OnSuccessfulLogin;

        // Rules created with a previous prefix would otherwise linger forever.
        var prefix = FirewallPlanner.SanitizePrefix(settings.General.FirewallRulePrefix);
        var previousPrefix = db.GetMeta("rule_prefix");
        if (previousPrefix is not null && !string.Equals(previousPrefix, prefix, StringComparison.Ordinal))
        {
            TryRemoveRules(previousPrefix);
        }

        db.SetMeta("rule_prefix", prefix);

        if (settings.General.ClearBansOnStartup)
        {
            engine.ClearAllBans();
        }

        monitors.Add(new LogFileMonitor(Submit, db, loggerFactory.CreateLogger<LogFileMonitor>(), time));
        foreach (var factory in monitorFactories)
        {
            try
            {
                monitors.Add(factory(Submit));
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unable to create a login monitor");
                AddStartupWarning("A login monitor could not be started: " + ex.Message);
            }
        }

        ConfigureMonitors();

        engine.RunHousekeeping();
        await SyncFirewallAsync(cancellationToken).ConfigureAwait(false);
        if (geo is not null)
        {
            _ = Task.Run(BackfillCountries, CancellationToken.None);
        }

        var token = shutdown.Token;
        loops.Add(Task.Run(() => ProcessEventsAsync(token), CancellationToken.None));
        loops.Add(Task.Run(() => CycleLoopAsync(token), CancellationToken.None));
        loops.Add(Task.Run(() => MaintenanceLoopAsync(token), CancellationToken.None));

        engine.Log(ActivityType.Info, $"TheFirewall service {Version} started.");
        logger.LogInformation("TheFirewall {Version} started; data directory {Directory}", Version, paths.DataDirectory);
    }

    /// <summary>Feeds a login event into the engine (thread-safe, non-blocking).</summary>
    public void Submit(LoginEvent evt) => events.Writer.TryWrite(evt);

    public void RequestFirewallSync() => syncRequests.Writer.TryWrite(true);

    // ------------------------------------------------------------------ Queries

    public ServiceStatusDto GetStatus()
    {
        var s = settings;
        var status = new ServiceStatusDto
        {
            Version = Version,
            MachineName = Environment.MachineName,
            StartedUtc = StartedUtc,
            ProtectionEnabled = s.ProtectionEnabled,
            ActiveBans = db?.GetBannedAddresses().Count ?? 0,
            FirewallName = backend.Name,
            FirewallProfiles = profileState,
            FirewallRuleCount = ruleCount,
            BlockedEntryCount = blockedEntries,
            LastFirewallSyncUtc = lastSyncUtc,
            FirewallError = firewallError,
            GeoDatabaseAvailable = geo is not null,
            GeoDatabaseVersion = GeoIpUpdater.GetInstalledVersion(paths.GeoDirectory),
            GeoDatabaseError = geoError,
            ActiveSources = monitors.SelectMany(m => m.GetStatuses()).Count(st => st.State == SourceState.Active),
            DataDirectory = paths.DataDirectory,
        };

        if (!s.ProtectionEnabled)
        {
            status.Warnings.Add("Protection is paused. Failed logins are recorded but nothing is banned.");
        }

        if (!profileState.Available)
        {
            status.Warnings.Add("Windows Defender Firewall is not available: " + (profileState.Error ?? "unknown error") +
                ". Bans cannot be enforced.");
        }
        else
        {
            var off = new List<string>();
            if (!profileState.DomainEnabled)
            {
                off.Add("Domain");
            }

            if (!profileState.PrivateEnabled)
            {
                off.Add("Private");
            }

            if (!profileState.PublicEnabled)
            {
                off.Add("Public");
            }

            if (off.Count > 0)
            {
                status.Warnings.Add($"Windows Defender Firewall is turned off for the {string.Join(", ", off)} profile{(off.Count > 1 ? "s" : string.Empty)}, so bans are not enforced there.");
            }
        }

        if (s.CountryBlocking.Mode != CountryBlockingMode.Off && geo is null)
        {
            status.Warnings.Add("Country blocking is on, but the country database has not been downloaded yet.");
        }

        if (geo is null && s.Ports.Any(PortNeedsCountries))
        {
            status.Warnings.Add("Some ports allow only certain countries, but the country database has not been downloaded yet, so those ports are open to everyone for now.");
        }

        if (firewallError is not null)
        {
            status.Warnings.Add("Some firewall rules could not be written: " + firewallError);
        }

        lock (startupWarnings)
        {
            status.Warnings.AddRange(startupWarnings);
        }

        return status;
    }

    public DashboardStats GetStats() => Database.GetDashboardStats(time.GetUtcNow());

    public List<ActivityEntry> QueryActivity(ActivityQuery query) => Database.QueryActivity(query);

    public List<IPRecord> GetBans() => Database.GetBannedRecords();

    public List<IPRecord> GetWatched(int limit) => Database.GetWatchedRecords(limit);

    public LookupResult Lookup(string ipText)
    {
        if (!IPUtility.TryParseAddress(ipText, out var address))
        {
            throw new IpcException($"'{ipText}' is not a valid IP address.");
        }

        var ip = address.ToString();
        var ctx = Engine.Context;
        return new LookupResult
        {
            IPAddress = ip,
            Country = geo?.Lookup(address),
            IsInternal = IPUtility.IsInternal(address),
            IsWhitelisted = ctx.IsWhitelisted(address, ip),
            IsBlacklisted = ctx.IsBlacklisted(address),
            Record = Database.GetRecord(ip),
            RecentActivity = Database.QueryActivity(new ActivityQuery { IPAddress = ip, Limit = 50 }),
        };
    }

    public List<SourceInfoDto> GetSources()
    {
        var statuses = monitors.SelectMany(m => m.GetStatuses()).ToDictionary(s => s.SourceId, StringComparer.OrdinalIgnoreCase);
        return SourceCatalog.GetEffective(settings).Select(def => new SourceInfoDto
        {
            Definition = def,
            IsBuiltIn = def.IsBuiltIn,
            Status = statuses.TryGetValue(def.Id, out var st) ? st : new SourceStatus
            {
                SourceId = def.Id,
                State = def.Enabled ? SourceState.NotDetected : SourceState.Disabled,
            },
        }).ToList();
    }

    public List<CountryDto> GetCountries()
    {
        var counts = geo?.CountRangesByCountry() ?? new Dictionary<string, int>();
        return Countries.All.Select(c => new CountryDto
        {
            Code = c.Code,
            Name = c.Name,
            Region = c.Region,
            RangeCount = counts.TryGetValue(c.Code, out var n) ? n : 0,
        }).ToList();
    }

    public List<FeedInfoDto> GetFeeds()
    {
        var statuses = feeds?.GetStatuses().ToDictionary(s => s.FeedId, StringComparer.OrdinalIgnoreCase) ?? [];
        return settings.ThreatFeeds.Select(f => new FeedInfoDto
        {
            Feed = f,
            Status = statuses.TryGetValue(f.Id, out var st) ? st : new ThreatFeedStatus { FeedId = f.Id },
        }).ToList();
    }

    public static SourceTestResult TestSource(SourceTestRequest request)
    {
        var result = new SourceTestResult();
        var def = request.Definition;
        var now = DateTimeOffset.UtcNow;
        try
        {
            if (def.Kind == LogSourceKind.TextFile)
            {
                var regex = LoginRegex.Create(def.Regex);
                var text = request.Sample.Replace("\r\n", "\n", StringComparison.Ordinal);
                foreach (var evt in LogFileMonitor.ParseText(def, regex, text.EndsWith('\n') ? text : text + "\n", now))
                {
                    result.Matches.Add(ToMatch(evt));
                }
            }
            else
            {
                foreach (var expression in def.Expressions)
                {
                    var error = LoginRegex.Validate(expression.Regex);
                    if (error is not null)
                    {
                        result.Error = $"Invalid regular expression for {expression.XPath}: {error}";
                        return result;
                    }
                }

                var navigator = EventXmlMatcher.CreateNavigator(request.Sample);
                if (navigator is null)
                {
                    result.Error = "The sample is not valid event XML. In Event Viewer open the event, choose the Details tab, select 'XML View' and copy the XML.";
                    return result;
                }

                var evt = EventXmlMatcher.Match(def, navigator, now);
                if (evt is not null)
                {
                    result.Matches.Add(ToMatch(evt));
                }
            }
        }
        catch (ArgumentException ex)
        {
            result.Error = "Invalid regular expression: " + ex.Message;
        }

        return result;

        static SourceTestMatch ToMatch(LoginEvent evt) => new()
        {
            IPAddress = evt.IPAddress,
            UserName = evt.UserName,
            Source = evt.Source,
            Log = evt.LogText,
            Timestamp = evt.Timestamp,
        };
    }

    // ------------------------------------------------------------------ Commands

    public void Ban(BanRequest request)
    {
        TimeSpan? duration = request.DurationMinutes switch
        {
            null => null,
            0 => TimeSpan.Zero,
            var m => TimeSpan.FromMinutes(Math.Max(1, m.Value)),
        };
        Engine.BanManually(request.IPAddress, duration, request.Reason);
    }

    public async Task<int> UnbanAsync(UnbanRequest request, CancellationToken cancellationToken)
    {
        int count = Engine.Unban(request.IPAddresses, request.AddToWhitelist ? "Unbanned and whitelisted" : "Unbanned manually");
        if (request.AddToWhitelist)
        {
            var updated = SettingsStore.Clone(settings);
            foreach (var ip in request.IPAddresses.Select(IPUtility.NormalizeText).OfType<string>())
            {
                if (!updated.Whitelist.Any(w => string.Equals(w.Value, ip, StringComparison.OrdinalIgnoreCase)))
                {
                    updated.Whitelist.Add(new AddressEntry { Value = ip, Comment = request.Comment ?? "Added from the ban list", AddedUtc = time.GetUtcNow() });
                }
            }

            await SaveSettingsAsync(updated, cancellationToken).ConfigureAwait(false);
        }

        return count;
    }

    public int ClearBans() => Engine.ClearAllBans();

    public int ImportBans(ImportBansRequest request)
    {
        int imported = 0;
        var now = time.GetUtcNow();
        foreach (var record in request.Bans.Where(b => b.IsBanned))
        {
            if (record.BanEndUtc is { } end && end <= now)
            {
                continue;
            }

            try
            {
                var remaining = record.BanEndUtc is { } e ? e - now : TimeSpan.Zero;
                Engine.BanManually(record.IPAddress, remaining, string.IsNullOrWhiteSpace(record.BanReason) ? "Imported" : "Imported: " + record.BanReason);
                imported++;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                logger.LogInformation("Skipped importing {IP}: {Reason}", record.IPAddress, ex.Message);
            }
        }

        return imported;
    }

    public async Task<SaveSettingsResponse> SaveSettingsAsync(FirewallSettings newSettings, CancellationToken cancellationToken)
    {
        SettingsStore.Normalize(newSettings);
        var errors = SettingsStore.Validate(newSettings);
        if (errors.Count > 0)
        {
            return new SaveSettingsResponse { Saved = false, Errors = errors };
        }

        await settingsLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var previous = settings;
            settingsStore.Save(newSettings);
            settings = newSettings;
            Engine.UpdateSettings(newSettings);
            ConfigureMonitors();

            var oldPrefix = FirewallPlanner.SanitizePrefix(previous.General.FirewallRulePrefix);
            var newPrefix = FirewallPlanner.SanitizePrefix(newSettings.General.FirewallRulePrefix);
            if (!string.Equals(oldPrefix, newPrefix, StringComparison.Ordinal))
            {
                TryRemoveRules(oldPrefix);
                Database.SetMeta("rule_prefix", newPrefix);
                lastBanChunks = null;
            }

            if (previous.ProtectionEnabled != newSettings.ProtectionEnabled)
            {
                Engine.Log(ActivityType.Info, newSettings.ProtectionEnabled ? "Protection resumed." : "Protection paused.");
            }

            bool geoNeeded = (newSettings.CountryBlocking.Mode != CountryBlockingMode.Off || newSettings.Ports.Any(PortNeedsCountries)) && geo is null;
            bool feedsChanged = !FeedsEqual(previous.ThreatFeeds, newSettings.ThreatFeeds);
            if (geoNeeded || feedsChanged)
            {
                _ = Task.Run(async () =>
                {
                    if (geoNeeded)
                    {
                        await UpdateGeoAsync(force: false, shutdown.Token).ConfigureAwait(false);
                    }

                    if (feedsChanged)
                    {
                        await RefreshFeedsAsync(force: false, shutdown.Token).ConfigureAwait(false);
                    }
                }, CancellationToken.None);
            }
        }
        finally
        {
            settingsLock.Release();
        }

        await SyncFirewallAsync(cancellationToken).ConfigureAwait(false);
        return new SaveSettingsResponse { Saved = true };
    }

    public async Task SetProtectionAsync(bool enabled, CancellationToken cancellationToken)
    {
        var updated = SettingsStore.Clone(settings);
        updated.ProtectionEnabled = enabled;
        await SaveSettingsAsync(updated, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> UpdateGeoAsync(bool force, CancellationToken cancellationToken)
    {
        var updater = new GeoIpUpdater(http, loggerFactory.CreateLogger<GeoIpUpdater>(), time);
        if (!force && !updater.IsUpdateDue(paths.GeoDirectory))
        {
            return false;
        }

        var updated = await updater.UpdateAsync(paths.GeoDirectory, cancellationToken).ConfigureAwait(false);
        if (updated is null)
        {
            geoError = "The country database could not be downloaded from db-ip.com. It will be retried later.";
            return false;
        }

        geo = updated;
        geoError = null;
        countryCache = null;
        BackfillCountries();
        Engine.Log(ActivityType.Info, $"Country database updated ({GeoIpUpdater.GetInstalledVersion(paths.GeoDirectory)}).");
        await SyncFirewallAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    public async Task RefreshFeedsAsync(bool force, CancellationToken cancellationToken)
    {
        if (feeds is null)
        {
            return;
        }

        if (await feeds.RefreshAsync(settings.ThreatFeeds, force, cancellationToken).ConfigureAwait(false))
        {
            await SyncFirewallAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task SyncFirewallAsync(CancellationToken cancellationToken)
    {
        if (synchronizer is null || db is null)
        {
            return;
        }

        await firewallLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var s = settings;
            try
            {
                profileState = backend.GetProfileState();
            }
            catch (Exception ex)
            {
                profileState = new FirewallProfileState { Available = false, Error = ex.Message };
            }

            var now = time.GetUtcNow();
            var plan = FirewallPlanner.Build(new FirewallPlanInput
            {
                Settings = s,
                BannedAddresses = db.GetBannedAddresses(),
                CountryRanges = GetCountryRanges(s),
                FeedRanges = feeds?.GetRanges(s.ThreatFeeds.Where(f => f.Enabled)) ?? new Dictionary<string, List<IPAddressRange>>(),
                PreviousBanChunks = lastBanChunks,
                Now = now,
                TimeZone = time.LocalTimeZone,
                CountryRangeLookup = GetPortCountryRanges,
            });
            lastPortStateKey = PortPolicy.StateKey(s.Ports, now, time.LocalTimeZone);

            var result = synchronizer.Apply(plan, FirewallPlanner.SanitizePrefix(s.General.FirewallRulePrefix));
            lastBanChunks = plan.BanChunks;
            ruleCount = plan.Rules.Count;
            blockedEntries = plan.BlockedEntryCount;
            lastSyncUtc = time.GetUtcNow();
            firewallError = result.Errors.Count == 0 ? null : string.Join("; ", result.Errors.Take(3));
        }
        catch (Exception ex)
        {
            firewallError = ex.Message;
            logger.LogError(ex, "Firewall synchronisation failed");
        }
        finally
        {
            firewallLock.Release();
        }

        StatusChanged?.Invoke(GetStatus());
    }

    /// <summary>
    /// Adds countries to history recorded while the country database was not available yet, so the dashboard's
    /// "Attacks by country" covers past activity too.
    /// </summary>
    public int BackfillCountries()
    {
        var database = geo;
        if (database is null || db is null)
        {
            return 0;
        }

        try
        {
            var countries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var ip in Database.GetAddressesWithoutCountry())
            {
                if (database.Lookup(ip) is { } country)
                {
                    countries[ip] = country;
                }
            }

            int updated = Database.SetCountries(countries);
            if (updated > 0)
            {
                logger.LogInformation("Added countries to {Count} earlier activity entries", updated);
            }

            return updated;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to add countries to earlier activity");
            return 0;
        }
    }

    /// <summary>Reads listening ports and Windows Firewall rules; set by the Windows service.</summary>
    public IPortInspector? PortInspector { get; set; }

    /// <summary>Ports programs on this computer listen on, and whether each one can be reached from the network.</summary>
    public ListeningPortsResponse GetListeningPorts()
    {
        var inspector = PortInspector;
        if (inspector is null)
        {
            return new ListeningPortsResponse { Error = "Listing ports is not available on this system." };
        }

        try
        {
            var ports = inspector.GetListeningPorts().ToList();
            var rules = inspector.GetInboundRules();
            var policy = inspector.GetPolicy();
            var s = settings;
            var now = time.GetUtcNow();
            foreach (var port in ports)
            {
                port.KnownName ??= PortCatalog.GetName(port.Port);
                PortReachability.Evaluate(port, rules, policy, s, now, time.LocalTimeZone);
            }

            return new ListeningPortsResponse
            {
                Ports = [.. ports.OrderBy(p => p.Port).ThenBy(p => p.Protocol, StringComparer.Ordinal)],
            };
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to list listening ports");
            return new ListeningPortsResponse { Error = "Unable to list listening ports: " + ex.Message };
        }
    }

    /// <summary>Deletes every firewall rule TheFirewall created (used on uninstall).</summary>
    public int RemoveAllRules() => synchronizer?.RemoveAll(FirewallPlanner.SanitizePrefix(settings.General.FirewallRulePrefix)) ?? 0;

    // ------------------------------------------------------------------ Internals

    private List<IPAddressRange>? GetCountryRanges(FirewallSettings s)
    {
        var country = s.CountryBlocking;
        if (country.Mode == CountryBlockingMode.Off || geo is null)
        {
            return null;
        }

        var key = string.Join(',', country.Countries.OrderBy(c => c, StringComparer.OrdinalIgnoreCase)) + "|" + geo.BuildDate.ToString("O", CultureInfo.InvariantCulture);
        if (countryCache is { } cache && cache.Key == key)
        {
            return cache.Ranges;
        }

        var ranges = geo.GetRanges(country.Countries);
        countryCache = (key, ranges);
        return ranges;
    }

    private static bool PortNeedsCountries(PortRule port) => port.Access == PortAccess.Restricted && port.AllowedCountries.Count > 0;

    /// <summary>Address ranges of the countries a port allows (cached per country list and database edition).</summary>
    private List<IPAddressRange>? GetPortCountryRanges(IReadOnlyCollection<string> codes)
    {
        var database = geo;
        if (database is null)
        {
            return null;
        }

        var key = string.Join(',', codes.Select(c => c.ToUpperInvariant()).Order(StringComparer.Ordinal)) + "|" +
                  database.BuildDate.ToString("O", CultureInfo.InvariantCulture);
        lock (portCountryCache)
        {
            if (!portCountryCache.TryGetValue(key, out var ranges))
            {
                if (portCountryCache.Count > 32)
                {
                    portCountryCache.Clear();
                }

                ranges = database.GetRanges(codes);
                portCountryCache[key] = ranges;
            }

            return ranges;
        }
    }

    private void ConfigureMonitors()
    {
        var sources = SourceCatalog.GetEffective(settings);
        foreach (var monitor in monitors)
        {
            try
            {
                monitor.Configure(sources);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unable to configure login monitor {Monitor}", monitor.GetType().Name);
            }
        }
    }

    private async Task ProcessEventsAsync(CancellationToken token)
    {
        try
        {
            await foreach (var evt in events.Reader.ReadAllAsync(token).ConfigureAwait(false))
            {
                try
                {
                    Engine.Process(evt);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Unable to process login event from {IP}", evt.IPAddress);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task CycleLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var delay = CancellationTokenSource.CreateLinkedTokenSource(token);
                var wait = Task.Delay(settings.General.CycleTime, time, delay.Token);
                var signal = syncRequests.Reader.WaitToReadAsync(delay.Token).AsTask();
                await Task.WhenAny(wait, signal).ConfigureAwait(false);
                await delay.CancelAsync().ConfigureAwait(false);
                token.ThrowIfCancellationRequested();

                bool requested = false;
                while (syncRequests.Reader.TryRead(out _))
                {
                    requested = true;
                }

                if (requested)
                {
                    // Give closely spaced bans a moment to arrive so they land in one firewall update.
                    await Task.Delay(TimeSpan.FromMilliseconds(750), time, token).ConfigureAwait(false);
                    while (syncRequests.Reader.TryRead(out _))
                    {
                    }
                }

                int expired = Engine.RunHousekeeping();

                // Port schedules and temporary openings: re-apply the rules when a port opens or closes by itself.
                bool portsChanged = settings.Ports.Count > 0 &&
                                    PortPolicy.StateKey(settings.Ports, time.GetUtcNow(), time.LocalTimeZone) != lastPortStateKey;
                if (requested || expired > 0 || portsChanged)
                {
                    await SyncFirewallAsync(token).ConfigureAwait(false);
                }

                var now = time.GetUtcNow();
                if (now >= nextActivityPrune)
                {
                    nextActivityPrune = now.AddHours(1);
                    Database.PruneActivity(now.AddDays(-settings.General.ActivityRetentionDays));
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Housekeeping cycle failed");
                await Task.Delay(TimeSpan.FromSeconds(5), time, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private async Task MaintenanceLoopAsync(CancellationToken token)
    {
        // Let the service settle before hitting the network.
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(20), time, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!token.IsCancellationRequested)
        {
            try
            {
                // The country database also labels addresses in the activity feed, so it is fetched even
                // when country blocking is off; after that it follows the auto-update setting.
                if (geo is null || settings.CountryBlocking.AutoUpdateDatabase)
                {
                    await UpdateGeoAsync(force: false, token).ConfigureAwait(false);
                }

                await RefreshFeedsAsync(force: false, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Maintenance failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromMinutes(15), time, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private void OnBanned(BanEventArgs args)
    {
        var actions = settings.Actions;
        if (string.IsNullOrWhiteSpace(actions.RunOnBan))
        {
            return;
        }

        launcher?.Run(actions.RunOnBan, new Dictionary<string, string?>
        {
            ["ip"] = args.Record.IPAddress,
            ["user"] = args.UserName,
            ["source"] = args.Source,
            ["country"] = args.Record.Country,
            ["count"] = args.Record.FailedCount.ToString(CultureInfo.InvariantCulture),
            ["reason"] = args.Reason,
            ["duration"] = TimeFormat.Duration(args.Duration),
            ["log"] = args.LogText,
        });
    }

    private void OnUnbanned(IPRecord record, string reason)
    {
        var actions = settings.Actions;
        if (!string.IsNullOrWhiteSpace(actions.RunOnUnban))
        {
            launcher?.Run(actions.RunOnUnban, new Dictionary<string, string?>
            {
                ["ip"] = record.IPAddress,
                ["source"] = record.Source,
                ["country"] = record.Country,
                ["reason"] = reason,
            });
        }
    }

    private void OnSuccessfulLogin(LoginEvent evt)
    {
        var actions = settings.Actions;
        if (!string.IsNullOrWhiteSpace(actions.RunOnSuccessfulLogin))
        {
            launcher?.Run(actions.RunOnSuccessfulLogin, new Dictionary<string, string?>
            {
                ["ip"] = evt.IPAddress,
                ["user"] = evt.UserName,
                ["source"] = evt.Source,
                ["country"] = geo?.Lookup(evt.IPAddress),
                ["log"] = evt.LogText,
            });
        }
    }

    private void TryRemoveRules(string prefix)
    {
        try
        {
            var removed = synchronizer?.RemoveAll(prefix) ?? 0;
            logger.LogInformation("Removed {Count} firewall rules with the old prefix {Prefix}", removed, prefix);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to remove rules with prefix {Prefix}", prefix);
        }
    }

    private static bool FeedsEqual(List<ThreatFeed> a, List<ThreatFeed> b) =>
        a.Count == b.Count && a.Zip(b).All(p => p.First.Id == p.Second.Id && p.First.Url == p.Second.Url && p.First.Enabled == p.Second.Enabled &&
                                                 p.First.MaxEntries == p.Second.MaxEntries);

    public async ValueTask DisposeAsync()
    {
        await shutdown.CancelAsync().ConfigureAwait(false);
        events.Writer.TryComplete();
        try
        {
            await Task.WhenAll(loops).WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Shutting down.
        }

        foreach (var monitor in monitors)
        {
            monitor.Dispose();
        }

        engine?.Log(ActivityType.Info, "TheFirewall service stopped.");
        db?.Dispose();
        shutdown.Dispose();
    }
}
