using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Security;
using Microsoft.Extensions.Logging;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Monitoring;

namespace TheFirewall.Service.Windows;

/// <summary>
/// Subscribes to Windows event logs and runs each event through the XPath/regex expressions of its source.
/// Every source has its own subscription with its own query, so a source only ever sees the events its query
/// selects (a shared subscription would hand, say, failed logons to the "successful sign-ins" source).
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsEventLogMonitor : ILoginMonitor
{
    private static readonly TimeSpan RetryInterval = TimeSpan.FromMinutes(5);

    private readonly Action<LoginEvent> sink;
    private readonly ILogger logger;
    private readonly object sync = new();
    private readonly Dictionary<string, LogSubscription> subscriptions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SourceRuntime> sources = new(StringComparer.OrdinalIgnoreCase);
    private readonly Timer retryTimer;
    private IReadOnlyList<LogSourceDefinition> configured = [];
    private HashSet<string>? logNames;

    public WindowsEventLogMonitor(Action<LoginEvent> sink, ILogger logger)
    {
        this.sink = sink;
        this.logger = logger;
        retryTimer = new Timer(_ => RetryMissingLogs(), null, RetryInterval, RetryInterval);
    }

    public void Configure(IReadOnlyList<LogSourceDefinition> definitions)
    {
        lock (sync)
        {
            configured = definitions.Where(d => d.Kind == LogSourceKind.EventLog).ToList();

            // Keep counters for sources that still exist.
            foreach (var id in sources.Keys.Where(id => !configured.Any(c => c.Id.Equals(id, StringComparison.OrdinalIgnoreCase))).ToList())
            {
                sources.Remove(id);
            }

            foreach (var def in configured)
            {
                if (sources.TryGetValue(def.Id, out var runtime))
                {
                    runtime.Definition = def;
                }
                else
                {
                    sources[def.Id] = new SourceRuntime(def);
                }
            }

            var wanted = configured.Where(d => d.Enabled && !string.IsNullOrWhiteSpace(d.LogName))
                .ToDictionary(d => d.Id, StringComparer.OrdinalIgnoreCase);

            foreach (var id in subscriptions.Keys.Where(k => !wanted.ContainsKey(k)).ToList())
            {
                subscriptions[id].Dispose();
                subscriptions.Remove(id);
            }

            logNames = null; // re-read the list of logs once per configuration
            foreach (var (id, def) in wanted)
            {
                var logName = def.LogName.Trim();
                var query = BuildQuery(logName, [def]);
                if (subscriptions.TryGetValue(id, out var existing))
                {
                    existing.Sources = [def];
                    if (string.Equals(existing.LogName, logName, StringComparison.OrdinalIgnoreCase) && existing.Query == query && existing.Watcher is not null)
                    {
                        continue;
                    }

                    existing.Dispose();
                    subscriptions.Remove(id);
                }

                var subscription = new LogSubscription(logName, query) { Sources = [def] };
                subscriptions[id] = subscription;
                Start(subscription);
            }

            UpdateStates();
        }
    }

    public IReadOnlyList<SourceStatus> GetStatuses()
    {
        lock (sync)
        {
            return sources.Values.Select(s => new SourceStatus
            {
                SourceId = s.Definition.Id,
                State = s.State,
                Message = s.Message,
                LastEventUtc = s.LastEventUtc,
                EventsDetected = s.EventsDetected,
            }).ToList();
        }
    }

    /// <summary>Combines the per-source XPath filters of one log into a structured query.</summary>
    internal static string BuildQuery(string logName, IReadOnlyList<LogSourceDefinition> defs)
    {
        var selects = defs.Any(d => string.IsNullOrWhiteSpace(d.Query))
            ? new List<string> { "*" }
            : defs.Select(d => d.Query.Trim()).Distinct(StringComparer.Ordinal).ToList();
        var path = SecurityElement.Escape(logName);
        var body = string.Concat(selects.Select(s => $"<Select Path=\"{path}\">{SecurityElement.Escape(s)}</Select>"));
        return $"<QueryList><Query Id=\"0\" Path=\"{path}\">{body}</Query></QueryList>";
    }

    private void Start(LogSubscription subscription)
    {
        // Subscriptions to a log that does not exist can succeed silently, so check explicitly
        // (otherwise monitors for software that is not installed would look active).
        if (!LogExists(subscription.LogName))
        {
            subscription.Missing = true;
            subscription.Error = null;
            return;
        }

        try
        {
            var query = new EventLogQuery(subscription.LogName, PathType.LogName, subscription.Query);
            var watcher = new EventLogWatcher(query, null, false);
            watcher.EventRecordWritten += (_, e) => OnEvent(subscription, e);
            watcher.Enabled = true;
            subscription.Watcher = watcher;
            subscription.Error = null;
            subscription.Missing = false;
            logger.LogInformation("Watching event log {Log} for {Source}", subscription.LogName, subscription.Sources.FirstOrDefault()?.Id);
        }
        catch (EventLogNotFoundException)
        {
            subscription.Missing = true;
            subscription.Error = null;
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            subscription.Error = ex.Message;
            logger.LogWarning(ex, "Unable to watch event log {Log}", subscription.LogName);
        }
    }

    private bool LogExists(string logName)
    {
        try
        {
            if (logNames is null)
            {
                using var session = new EventLogSession();
                logNames = new HashSet<string>(session.GetLogNames(), StringComparer.OrdinalIgnoreCase);
            }

            return logNames.Contains(logName);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Unable to list event logs; assuming {Log} exists", logName);
            return true;
        }
    }

    private void OnEvent(LogSubscription subscription, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null)
        {
            logger.LogWarning(e.EventException, "Error reading event log {Log}", subscription.LogName);
            return;
        }

        using var record = e.EventRecord;
        if (record is null)
        {
            return;
        }

        string xml;
        try
        {
            xml = record.ToXml();
        }
        catch (EventLogException ex)
        {
            logger.LogDebug(ex, "Unable to read event XML from {Log}", subscription.LogName);
            return;
        }

        var navigator = EventXmlMatcher.CreateNavigator(xml);
        if (navigator is null)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        foreach (var def in subscription.Sources)
        {
            LoginEvent? evt;
            try
            {
                evt = EventXmlMatcher.Match(def, navigator, now);
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Source {Source} failed to evaluate an event", def.Id);
                continue;
            }

            if (evt is null)
            {
                continue;
            }

            lock (sync)
            {
                if (sources.TryGetValue(def.Id, out var runtime))
                {
                    runtime.EventsDetected++;
                    runtime.LastEventUtc = now;
                }
            }

            sink(evt);
        }
    }

    private void RetryMissingLogs()
    {
        lock (sync)
        {
            bool changed = false;
            logNames = null;
            foreach (var subscription in subscriptions.Values.Where(s => s.Watcher is null))
            {
                Start(subscription);
                changed |= subscription.Watcher is not null;
            }

            if (changed)
            {
                UpdateStates();
            }
        }
    }

    private void UpdateStates()
    {
        foreach (var runtime in sources.Values)
        {
            var def = runtime.Definition;
            if (!def.Enabled)
            {
                runtime.State = SourceState.Disabled;
                runtime.Message = null;
                continue;
            }

            if (!subscriptions.TryGetValue(def.Id, out var subscription))
            {
                runtime.State = SourceState.Error;
                runtime.Message = "No event log name configured.";
                continue;
            }

            if (subscription.Watcher is not null)
            {
                runtime.State = SourceState.Active;
                runtime.Message = null;
            }
            else if (subscription.Missing)
            {
                runtime.State = SourceState.NotDetected;
                runtime.Message = $"The event log '{def.LogName}' does not exist on this computer.";
            }
            else
            {
                runtime.State = SourceState.Error;
                runtime.Message = subscription.Error;
            }
        }
    }

    public void Dispose()
    {
        retryTimer.Dispose();
        lock (sync)
        {
            foreach (var subscription in subscriptions.Values)
            {
                subscription.Dispose();
            }

            subscriptions.Clear();
        }
    }

    private sealed class LogSubscription(string logName, string query) : IDisposable
    {
        public string LogName { get; } = logName;

        public string Query { get; } = query;

        public List<LogSourceDefinition> Sources { get; set; } = [];

        public EventLogWatcher? Watcher { get; set; }

        public bool Missing { get; set; }

        public string? Error { get; set; }

        public void Dispose()
        {
            if (Watcher is not null)
            {
                try
                {
                    Watcher.Enabled = false;
                }
                catch (Exception)
                {
                }

                Watcher.Dispose();
                Watcher = null;
            }
        }
    }

    private sealed class SourceRuntime(LogSourceDefinition definition)
    {
        public LogSourceDefinition Definition { get; set; } = definition;

        public SourceState State { get; set; } = SourceState.Disabled;

        public string? Message { get; set; }

        public DateTimeOffset? LastEventUtc { get; set; }

        public long EventsDetected { get; set; }
    }
}
