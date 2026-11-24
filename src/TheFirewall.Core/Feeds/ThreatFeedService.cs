using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Feeds;

public sealed class ThreatFeedStatus
{
    public string FeedId { get; set; } = string.Empty;

    public DateTimeOffset? LastUpdatedUtc { get; set; }

    public int EntryCount { get; set; }

    public string? LastError { get; set; }
}

/// <summary>Downloads external IP block lists and keeps their parsed ranges in memory (cached on disk).</summary>
public sealed class ThreatFeedService(string cacheDirectory, HttpClient http, ILogger logger, TimeProvider? time = null)
{
    private readonly TimeProvider time = time ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, List<IPAddressRange>> ranges = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ThreatFeedStatus> statuses = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<ThreatFeedStatus> GetStatuses() => [.. statuses.Values];

    public IReadOnlyDictionary<string, List<IPAddressRange>> GetRanges(IEnumerable<ThreatFeed> enabledFeeds)
    {
        var result = new Dictionary<string, List<IPAddressRange>>(StringComparer.OrdinalIgnoreCase);
        foreach (var feed in enabledFeeds)
        {
            if (ranges.TryGetValue(feed.Id, out var list))
            {
                result[feed.Id] = list;
            }
        }

        return result;
    }

    /// <summary>Loads cached feed files from disk (called at startup so blocking resumes before any download).</summary>
    public void LoadCache(IEnumerable<ThreatFeed> feeds)
    {
        foreach (var feed in feeds.Where(f => f.Enabled))
        {
            var path = CachePath(feed);
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                var parsed = Parse(File.ReadAllText(path), feed.MaxEntries);
                ranges[feed.Id] = parsed;
                statuses[feed.Id] = new ThreatFeedStatus { FeedId = feed.Id, EntryCount = parsed.Count, LastUpdatedUtc = File.GetLastWriteTimeUtc(path) };
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Unable to load cached feed {Feed}", feed.Name);
            }
        }
    }

    /// <summary>Refreshes the feeds that are due. Returns true when any feed's contents changed.</summary>
    public async Task<bool> RefreshAsync(IEnumerable<ThreatFeed> feeds, bool force, CancellationToken cancellationToken)
    {
        bool changed = false;
        var feedList = feeds.ToList();

        // Forget disabled or deleted feeds.
        foreach (var id in ranges.Keys.Where(id => !feedList.Any(f => f.Enabled && f.Id.Equals(id, StringComparison.OrdinalIgnoreCase))).ToList())
        {
            ranges.TryRemove(id, out _);
            statuses.TryRemove(id, out _);
            changed = true;
        }

        foreach (var feed in feedList.Where(f => f.Enabled && !string.IsNullOrWhiteSpace(f.Url)))
        {
            var status = statuses.GetOrAdd(feed.Id, id => new ThreatFeedStatus { FeedId = id });
            var due = status.LastUpdatedUtc is null || time.GetUtcNow() - status.LastUpdatedUtc >= TimeSpan.FromHours(Math.Max(1, feed.RefreshHours));
            if (!force && !due && ranges.ContainsKey(feed.Id))
            {
                continue;
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, feed.Url);
                using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                var parsed = Parse(text, feed.MaxEntries);
                if (parsed.Count == 0)
                {
                    throw new InvalidDataException("The list did not contain any IP addresses.");
                }

                Directory.CreateDirectory(cacheDirectory);
                await File.WriteAllTextAsync(CachePath(feed), text, cancellationToken).ConfigureAwait(false);
                ranges[feed.Id] = parsed;
                status.EntryCount = parsed.Count;
                status.LastUpdatedUtc = time.GetUtcNow();
                status.LastError = null;
                changed = true;
                logger.LogInformation("Threat feed {Feed} refreshed: {Count} entries", feed.Name, parsed.Count);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                status.LastError = ex.Message;

                // Retry in an hour rather than every cycle.
                status.LastUpdatedUtc = time.GetUtcNow() - TimeSpan.FromHours(Math.Max(1, feed.RefreshHours)) + TimeSpan.FromHours(1);
                logger.LogWarning(ex, "Unable to refresh threat feed {Feed}", feed.Name);
            }
        }

        return changed;
    }

    /// <summary>
    /// Extracts the first IP address, CIDR block or range from each line. Handles plain lists, "ip ; comment"
    /// formats, tab separated lists with scores and JSON lines such as {"cidr":"1.2.3.0/24"}.
    /// </summary>
    public static List<IPAddressRange> Parse(string text, int maxEntries = int.MaxValue)
    {
        var result = new List<IPAddressRange>();
        char[] separators = [' ', '\t', ',', ';', '"', '\'', '{', '}', '[', ']', '|'];
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line[0] is '#' or ';' or '/')
            {
                continue;
            }

            foreach (var token in line.Split(separators, StringSplitOptions.RemoveEmptyEntries))
            {
                if (token.Length >= 7 && IPAddressRange.TryParse(token, out var range))
                {
                    result.Add(range);
                    break;
                }
            }

            if (result.Count >= maxEntries)
            {
                break;
            }
        }

        return IPAddressRange.Merge(result);
    }

    private string CachePath(ThreatFeed feed)
    {
        var safe = string.Concat(feed.Id.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_'));
        return Path.Combine(cacheDirectory, $"{safe}.txt");
    }
}
