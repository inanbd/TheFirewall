using System.Collections.Concurrent;
using System.Globalization;
using System.Text.RegularExpressions;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Monitoring;

/// <summary>
/// Regular expression helpers shared by event log and text file sources. Patterns may span several lines;
/// each line is trimmed and the lines are joined (so use \s for leading or trailing spaces), the same
/// convention IPBan uses, which keeps long alternations readable.
/// </summary>
public static class LoginRegex
{
    public static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(2);

    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Multiline;

    private static readonly ConcurrentDictionary<string, Regex> Cache = new(StringComparer.Ordinal);

    public static string Normalize(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return string.Empty;
        }

        var lines = pattern.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n');
        return string.Concat(lines.Select(l => l.Trim()));
    }

    /// <summary>Returns a compiled, cached regex or null for an empty pattern. Throws <see cref="ArgumentException"/> for invalid patterns.</summary>
    public static Regex? Get(string pattern)
    {
        var normalized = Normalize(pattern);
        if (normalized.Length == 0)
        {
            return null;
        }

        return Cache.GetOrAdd(normalized, static p => new Regex(p, Options | RegexOptions.Compiled, MatchTimeout));
    }

    /// <summary>Validates a pattern, returning an error message or null when it is valid.</summary>
    public static string? Validate(string pattern)
    {
        try
        {
            var normalized = Normalize(pattern);
            if (normalized.Length > 0)
            {
                _ = new Regex(normalized, Options, MatchTimeout);
            }

            return null;
        }
        catch (ArgumentException ex)
        {
            return ex.Message;
        }
    }

    /// <summary>Creates an uncached regex, used for one-off tests from the UI.</summary>
    public static Regex Create(string pattern) => new(Normalize(pattern), Options, MatchTimeout);
}

/// <summary>Accumulates named-group captures from one or more regex matches.</summary>
public sealed class MatchCapture
{
    public string? IPAddress { get; private set; }

    public string? UserName { get; private set; }

    public string? Source { get; private set; }

    public string? Log { get; private set; }

    public DateTimeOffset? Timestamp { get; private set; }

    /// <summary>
    /// Applies a match. Returns false when the match contains an IP address group whose value is not a valid IP,
    /// in which case nothing is captured.
    /// </summary>
    public bool TryApply(Match match, string? timestampFormat = null)
    {
        string? ip = null;
        bool hasIpGroup = false;
        foreach (var name in new[] { "ipaddress_exact", "ipaddress" })
        {
            var g = match.Groups[name];
            if (g.Success && g.Value.Length > 0)
            {
                hasIpGroup = true;
                ip = IPUtility.NormalizeText(g.Value);
                if (ip is not null)
                {
                    break;
                }
            }
        }

        if (hasIpGroup && ip is null)
        {
            return false;
        }

        if (ip is not null)
        {
            IPAddress = ip;
        }

        foreach (Group group in match.Groups)
        {
            if (!group.Success || group.Value.Length == 0)
            {
                continue;
            }

            switch (group.Name.ToLowerInvariant())
            {
                case "username":
                    UserName = CleanUserName(group.Value);
                    break;
                case "source":
                    Source = group.Value.Trim();
                    break;
                case "log":
                    Log = group.Value.Trim();
                    break;
                case "timestamp":
                    Timestamp = ParseTimestamp(group.Value, timestampFormat, assumeUtc: false) ?? Timestamp;
                    break;
                case "timestamp_utc":
                    Timestamp = ParseTimestamp(group.Value, timestampFormat, assumeUtc: true) ?? Timestamp;
                    break;
                default:
                    if (group.Name.StartsWith("source_", StringComparison.OrdinalIgnoreCase) && group.Name.Length > 7)
                    {
                        Source = group.Name[7..];
                    }

                    break;
            }
        }

        return true;
    }

    internal static string? CleanUserName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim().Trim('"', '\'');
        return trimmed is "-" or "" ? null : trimmed;
    }

    internal static DateTimeOffset? ParseTimestamp(string value, string? format, bool assumeUtc)
    {
        value = value.Trim();
        var styles = assumeUtc
            ? DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal
            : DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal;
        if (!string.IsNullOrWhiteSpace(format) &&
            DateTimeOffset.TryParseExact(value, format, CultureInfo.InvariantCulture, styles, out var exact))
        {
            return exact;
        }

        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, styles, out var parsed) ? parsed : null;
    }
}
