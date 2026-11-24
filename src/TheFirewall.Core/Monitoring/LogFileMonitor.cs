using System.Globalization;
using System.Text;
using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.Logging;
using TheFirewall.Core.Configuration;

namespace TheFirewall.Core.Monitoring;

/// <summary>
/// Tails text log files that match the path masks of text-file sources and applies each source's regex
/// to newly appended lines.
/// </summary>
public sealed class LogFileMonitor : ILoginMonitor
{
    /// <summary>Never read more than this per file and poll; older backlog is skipped.</summary>
    internal const int MaxReadBytes = 16 * 1024 * 1024;

    private const int RegexChunkSize = 512 * 1024;

    private readonly Action<LoginEvent> sink;
    private readonly IFilePositionStore? positionStore;
    private readonly ILogger logger;
    private readonly TimeProvider time;
    private readonly object sync = new();
    private readonly Dictionary<string, long> positions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SourceRuntime> sources = new(StringComparer.OrdinalIgnoreCase);
    private bool positionsDirty;
    private DateTimeOffset nextPruneUtc = DateTimeOffset.MinValue;
    private Timer? timer;
    private int polling;

    public LogFileMonitor(Action<LoginEvent> sink, IFilePositionStore? positionStore, ILogger logger, TimeProvider? time = null)
    {
        this.sink = sink;
        this.positionStore = positionStore;
        this.logger = logger;
        this.time = time ?? TimeProvider.System;
        if (positionStore is not null)
        {
            foreach (var (path, pos) in positionStore.LoadFilePositions())
            {
                positions[path] = pos;
            }
        }
    }

    public void Configure(IReadOnlyList<LogSourceDefinition> definitions)
    {
        lock (sync)
        {
            var wanted = definitions.Where(d => d.Kind == LogSourceKind.TextFile).ToList();
            var keep = new HashSet<string>(wanted.Select(w => w.Id), StringComparer.OrdinalIgnoreCase);
            foreach (var id in sources.Keys.Where(k => !keep.Contains(k)).ToList())
            {
                sources.Remove(id);
            }

            foreach (var def in wanted)
            {
                if (sources.TryGetValue(def.Id, out var existing) && existing.Matches(def))
                {
                    existing.Definition = def;
                    continue;
                }

                sources[def.Id] = new SourceRuntime(def);
            }
        }

        timer ??= new Timer(_ => PollAll(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
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
                FilesWatched = s.FilesWatched,
            }).ToList();
        }
    }

    /// <summary>Polls every source that is due. Public for tests; normally driven by an internal timer.</summary>
    public void PollAll(bool force = false)
    {
        if (Interlocked.Exchange(ref polling, 1) == 1)
        {
            return;
        }

        try
        {
            List<SourceRuntime> due;
            var now = time.GetUtcNow();
            lock (sync)
            {
                due = sources.Values.Where(s => force || s.NextPollUtc <= now).ToList();
            }

            foreach (var source in due)
            {
                PollSource(source, now);
                source.NextPollUtc = now.AddSeconds(Math.Max(1, source.Definition.PollIntervalSeconds));
            }

            if (now >= nextPruneUtc)
            {
                nextPruneUtc = now.AddMinutes(10);
                PruneMissingFiles();
            }

            SavePositionsIfDirty();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error while polling log files");
        }
        finally
        {
            Interlocked.Exchange(ref polling, 0);
        }
    }

    private void PollSource(SourceRuntime source, DateTimeOffset now)
    {
        var def = source.Definition;
        if (!def.Enabled)
        {
            source.State = SourceState.Disabled;
            source.Message = null;
            return;
        }

        var regex = LoginRegex.Get(def.Regex);
        if (regex is null)
        {
            source.State = SourceState.Error;
            source.Message = "No regular expression configured.";
            return;
        }

        bool anyBaseDirectory = false;
        var files = new List<string>();
        try
        {
            foreach (var mask in SplitMasks(def.PathMasks))
            {
                files.AddRange(ExpandMask(mask, now, ref anyBaseDirectory));
            }
        }
        catch (Exception ex)
        {
            source.State = SourceState.Error;
            source.Message = ex.Message;
            return;
        }

        source.FilesWatched = files.Count;
        if (files.Count == 0)
        {
            source.State = SourceState.NotDetected;
            source.Message = anyBaseDirectory ? "Waiting for log files to appear." : "Log folder not found on this computer.";
            source.InitialScanDone = true;
            return;
        }

        source.State = SourceState.Active;
        source.Message = null;

        foreach (var file in files.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                ReadFile(source, file, regex, now);
            }
            catch (IOException ex)
            {
                logger.LogDebug(ex, "Unable to read {File}", file);
            }
            catch (UnauthorizedAccessException ex)
            {
                source.State = SourceState.Error;
                source.Message = $"Access denied: {file}";
                logger.LogDebug(ex, "Access denied reading {File}", file);
            }
        }

        source.InitialScanDone = true;
    }

    private void ReadFile(SourceRuntime source, string file, System.Text.RegularExpressions.Regex regex, DateTimeOffset now)
    {
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        long length = stream.Length;
        long position;
        lock (sync)
        {
            if (!positions.TryGetValue(file, out position))
            {
                // Existing files seen on the first scan start at the end so old history is not replayed.
                // Files that appear later (log rotation) are read from the start.
                position = source.InitialScanDone ? 0 : length;
                positions[file] = position;
                positionsDirty = true;
            }
        }

        if (position > length)
        {
            position = 0; // truncated or replaced
        }

        if (length - position > MaxReadBytes)
        {
            position = length - MaxReadBytes;
        }

        if (position == length)
        {
            return;
        }

        stream.Seek(position, SeekOrigin.Begin);
        var buffer = new byte[length - position];
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer, total, buffer.Length - total);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        int lastNewline = Array.LastIndexOf(buffer, (byte)'\n', total - 1);
        if (lastNewline < 0)
        {
            // Incomplete line; wait for more data unless the line is absurdly long.
            if (total < 64 * 1024)
            {
                return;
            }

            lastNewline = total - 1;
        }

        int start = 0;
        if (position == 0 && total >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
        {
            start = 3;
        }

        var text = Encoding.UTF8.GetString(buffer, start, lastNewline + 1 - start).Replace("\r\n", "\n", StringComparison.Ordinal);
        lock (sync)
        {
            positions[file] = position + lastNewline + 1;
            positionsDirty = true;
        }

        foreach (var evt in ParseText(source.Definition, regex, text, now))
        {
            source.EventsDetected++;
            source.LastEventUtc = now;
            sink(evt);
        }
    }

    /// <summary>Applies a text source's regex to a block of log text.</summary>
    public static IEnumerable<LoginEvent> ParseText(LogSourceDefinition def, System.Text.RegularExpressions.Regex regex, string text, DateTimeOffset now)
    {
        foreach (var chunk in ChunkAtLines(text, RegexChunkSize))
        {
            System.Text.RegularExpressions.MatchCollection matches;
            var results = new List<LoginEvent>();
            try
            {
                matches = regex.Matches(chunk);
                foreach (System.Text.RegularExpressions.Match match in matches)
                {
                    var capture = new MatchCapture();
                    if (!capture.TryApply(match, def.TimestampFormat) || capture.IPAddress is null)
                    {
                        continue;
                    }

                    var timestamp = capture.Timestamp;
                    if (timestamp is null || timestamp > now.AddMinutes(5) || timestamp < now.AddHours(-1))
                    {
                        timestamp = now;
                    }

                    var logText = capture.Log ?? match.Value.Trim();
                    results.Add(new LoginEvent
                    {
                        IPAddress = capture.IPAddress,
                        UserName = capture.UserName,
                        Source = string.IsNullOrWhiteSpace(capture.Source) ? def.Source : capture.Source,
                        SourceId = def.Id,
                        Kind = def.EventKind,
                        Timestamp = timestamp.Value,
                        LogText = logText.Length > 300 ? logText[..300] : logText,
                        FailedAttemptsBeforeBan = def.FailedAttemptsBeforeBan,
                    });
                }
            }
            catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
            {
                // Pathological input; skip this chunk rather than stall monitoring.
            }

            foreach (var r in results)
            {
                yield return r;
            }
        }
    }

    private static IEnumerable<string> ChunkAtLines(string text, int chunkSize)
    {
        int start = 0;
        while (start < text.Length)
        {
            if (text.Length - start <= chunkSize)
            {
                yield return text[start..];
                yield break;
            }

            int end = text.LastIndexOf('\n', start + chunkSize, chunkSize);
            if (end <= start)
            {
                end = start + chunkSize;
            }

            yield return text[start..(end + 1 > text.Length ? text.Length : end + 1)];
            start = end + 1;
        }
    }

    internal static IEnumerable<string> SplitMasks(string masks) =>
        masks.Split(['\n', '\r', '|'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    internal static string ReplacePlaceholders(string mask, DateTimeOffset utcNow)
    {
        var local = utcNow.ToLocalTime();
        return mask
            .Replace("{year-local}", local.Year.ToString("0000", CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase)
            .Replace("{month-local}", local.Month.ToString("00", CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase)
            .Replace("{day-local}", local.Day.ToString("00", CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase)
            .Replace("{year}", utcNow.Year.ToString("0000", CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase)
            .Replace("{month}", utcNow.Month.ToString("00", CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase)
            .Replace("{day}", utcNow.Day.ToString("00", CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Expands one path mask (with globbing and placeholders) into existing files.</summary>
    internal static List<string> ExpandMask(string mask, DateTimeOffset utcNow, ref bool baseDirectoryExists)
    {
        var result = new List<string>();
        var expanded = ReplacePlaceholders(Environment.ExpandEnvironmentVariables(mask.Trim()), utcNow).Replace('\\', '/');
        var segments = expanded.Split('/');
        int firstWild = Array.FindIndex(segments, s => s.IndexOfAny(['*', '?', '[']) >= 0);
        if (firstWild < 0)
        {
            var dir = Path.GetDirectoryName(expanded);
            if (dir is not null && Directory.Exists(dir))
            {
                baseDirectoryExists = true;
            }

            if (File.Exists(expanded))
            {
                result.Add(Path.GetFullPath(expanded));
            }

            return result;
        }

        if (firstWild == 0)
        {
            return result; // relative masks are not supported
        }

        var baseDir = string.Join('/', segments[..firstWild]);
        if (baseDir.Length == 0)
        {
            baseDir = "/";
        }
        else if (baseDir.EndsWith(':'))
        {
            baseDir += "/";
        }

        if (!Directory.Exists(baseDir))
        {
            return result;
        }

        baseDirectoryExists = true;
        var matcher = new Matcher(StringComparison.OrdinalIgnoreCase);
        matcher.AddInclude(string.Join('/', segments[firstWild..]));
        result.AddRange(matcher.GetResultsInFullPath(baseDir));
        return result;
    }

    private void PruneMissingFiles()
    {
        List<string> known;
        lock (sync)
        {
            known = positions.Keys.ToList();
        }

        var missing = known.Where(path => !File.Exists(path)).ToList();
        if (missing.Count == 0)
        {
            return;
        }

        lock (sync)
        {
            foreach (var path in missing)
            {
                positions.Remove(path);
            }

            positionsDirty = true;
        }
    }

    private void SavePositionsIfDirty()
    {
        Dictionary<string, long>? snapshot = null;
        lock (sync)
        {
            if (positionsDirty)
            {
                positionsDirty = false;
                snapshot = new Dictionary<string, long>(positions, StringComparer.OrdinalIgnoreCase);
            }
        }

        if (snapshot is not null)
        {
            try
            {
                positionStore?.SaveFilePositions(snapshot);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Unable to save log file positions");
            }
        }
    }

    public void Dispose()
    {
        timer?.Dispose();
        timer = null;
        SavePositionsIfDirty();
    }

    private sealed class SourceRuntime(LogSourceDefinition definition)
    {
        public LogSourceDefinition Definition { get; set; } = definition;

        public DateTimeOffset NextPollUtc { get; set; } = DateTimeOffset.MinValue;

        public bool InitialScanDone { get; set; }

        public SourceState State { get; set; } = SourceState.Active;

        public string? Message { get; set; }

        public DateTimeOffset? LastEventUtc { get; set; }

        public long EventsDetected { get; set; }

        public int FilesWatched { get; set; }

        public bool Matches(LogSourceDefinition other) =>
            Definition.PathMasks == other.PathMasks && Definition.Regex == other.Regex;
    }
}
