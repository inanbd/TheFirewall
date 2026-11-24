using System.Net;
using System.Text.RegularExpressions;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Monitoring;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Engine;

/// <summary>Pre-computed lookups derived from the settings (whitelist ranges, compiled regexes, user name sets).</summary>
public sealed class PolicyContext
{
    public PolicyContext(FirewallSettings settings)
    {
        Settings = settings;
        Whitelist = IPAddressRange.Merge(settings.Whitelist
            .Select(w => IPAddressRange.TryParse(w.Value, out var r) ? (IPAddressRange?)r : null)
            .Where(r => r is not null).Select(r => r!.Value));
        Blacklist = IPAddressRange.Merge(settings.Blacklist
            .Select(w => IPAddressRange.TryParse(w.Value, out var r) ? (IPAddressRange?)r : null)
            .Where(r => r is not null).Select(r => r!.Value));
        WhitelistRegex = TryCreate(settings.WhitelistRegex);
        BlacklistRegex = TryCreate(settings.BlacklistRegex);
        InstantBanUserNames = new HashSet<string>(settings.UserNames.InstantBanUserNames.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()),
            StringComparer.OrdinalIgnoreCase);
        AllowedUserNames = settings.UserNames.AllowedUserNames.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim().ToLowerInvariant()).Distinct().ToList();
    }

    public FirewallSettings Settings { get; }

    public IReadOnlyList<IPAddressRange> Whitelist { get; }

    public IReadOnlyList<IPAddressRange> Blacklist { get; }

    public Regex? WhitelistRegex { get; }

    public Regex? BlacklistRegex { get; }

    public HashSet<string> InstantBanUserNames { get; }

    public IReadOnlyList<string> AllowedUserNames { get; }

    public bool IsWhitelisted(IPAddress address, string text)
    {
        foreach (var range in Whitelist)
        {
            if (range.Contains(address))
            {
                return true;
            }
        }

        return SafeIsMatch(WhitelistRegex, text);
    }

    public bool IsBlacklisted(IPAddress address)
    {
        foreach (var range in Blacklist)
        {
            if (range.Contains(address))
            {
                return true;
            }
        }

        return false;
    }

    public bool MatchesBlacklistRegex(string ip, string? userName) =>
        SafeIsMatch(BlacklistRegex, ip) || (userName is not null && SafeIsMatch(BlacklistRegex, userName));

    /// <summary>True when the user name is on the allowed list (or within the configured edit distance of an entry).</summary>
    public bool IsAllowedUserName(string userName)
    {
        var lower = userName.ToLowerInvariant();
        int maxDistance = Math.Max(0, Settings.UserNames.AllowedUserNameEditDistance);
        foreach (var allowed in AllowedUserNames)
        {
            if (allowed == lower || (maxDistance > 0 && Levenshtein(allowed, lower, maxDistance) <= maxDistance))
            {
                return true;
            }
        }

        return false;
    }

    public string? NormalizeUserName(string? userName)
    {
        var clean = MatchCapture.CleanUserName(userName);
        if (clean is null)
        {
            return null;
        }

        var chars = Settings.UserNames.TruncateUserNameChars;
        if (!string.IsNullOrEmpty(chars))
        {
            int index = clean.IndexOfAny(chars.ToCharArray());
            if (index > 0)
            {
                clean = clean[..index];
            }
        }

        // DOMAIN\user -> user
        int slash = clean.LastIndexOf('\\');
        if (slash >= 0 && slash < clean.Length - 1)
        {
            clean = clean[(slash + 1)..];
        }

        return clean.Length == 0 ? null : clean;
    }

    private static bool SafeIsMatch(Regex? regex, string text)
    {
        if (regex is null)
        {
            return false;
        }

        try
        {
            return regex.IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static Regex? TryCreate(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return null;
        }

        // Shortcut used by IPBan: "128.128.128.*" style wildcards.
        var normalized = pattern.Trim();
        if (!normalized.Contains('\\') && !normalized.Contains('(') && normalized.Contains('*') && !normalized.Contains(".*"))
        {
            normalized = "^" + Regex.Escape(normalized).Replace("\\*", ".*", StringComparison.Ordinal) + "$";
        }

        try
        {
            return LoginRegex.Create(normalized);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    internal static int Levenshtein(string a, string b, int max)
    {
        if (Math.Abs(a.Length - b.Length) > max)
        {
            return max + 1;
        }

        var previous = new int[b.Length + 1];
        var current = new int[b.Length + 1];
        for (int j = 0; j <= b.Length; j++)
        {
            previous[j] = j;
        }

        for (int i = 1; i <= a.Length; i++)
        {
            current[0] = i;
            for (int j = 1; j <= b.Length; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                current[j] = Math.Min(Math.Min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost);
            }

            (previous, current) = (current, previous);
        }

        return previous[b.Length];
    }
}
