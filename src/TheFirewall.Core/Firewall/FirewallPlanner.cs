using System.Globalization;
using System.Net.Sockets;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Firewall;

/// <summary>Everything the planner needs to compute the desired rule set.</summary>
public sealed class FirewallPlanInput
{
    public required FirewallSettings Settings { get; init; }

    public IReadOnlyCollection<string> BannedAddresses { get; init; } = [];

    /// <summary>Ranges of the selected countries (already merged). Null when the GeoIP database is unavailable.</summary>
    public IReadOnlyList<IPAddressRange>? CountryRanges { get; init; }

    public IReadOnlyDictionary<string, List<IPAddressRange>> FeedRanges { get; init; } = new Dictionary<string, List<IPAddressRange>>();

    /// <summary>Ban rule membership from the previous plan, used to keep rules stable when addresses come and go.</summary>
    public IReadOnlyDictionary<string, List<string>>? PreviousBanChunks { get; init; }
}

public sealed class FirewallPlan
{
    public List<FirewallRuleSpec> Rules { get; } = [];

    public Dictionary<string, List<string>> BanChunks { get; } = new(StringComparer.OrdinalIgnoreCase);

    public int BlockedEntryCount { get; set; }
}

/// <summary>Turns settings, bans, country ranges and threat feeds into Windows Firewall rules.</summary>
public static class FirewallPlanner
{
    /// <summary>Windows Firewall handles large address lists best when split into rules of this size.</summary>
    public const int MaxAddressesPerRule = 1000;

    public static FirewallPlan Build(FirewallPlanInput input)
    {
        var settings = input.Settings;
        var prefix = SanitizePrefix(settings.General.FirewallRulePrefix);
        var plan = new FirewallPlan();
        bool active = settings.ProtectionEnabled;

        var whitelist = settings.Whitelist.Select(w => IPAddressRange.TryParse(w.Value, out var r) ? (IPAddressRange?)r : null)
            .Where(r => r is not null).Select(r => r!.Value).ToList();
        var protectedRanges = new List<IPAddressRange>(whitelist);
        if (!settings.BanPolicy.ProcessInternalAddresses)
        {
            protectedRanges.AddRange(IPUtility.InternalAddressRanges);
        }

        // ---- Bans (stable chunking so one new ban touches one rule)
        var bannedSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var ip in input.BannedAddresses)
        {
            var normalized = IPUtility.NormalizeText(ip);
            if (normalized is not null && !whitelist.Any(w => w.Contains(System.Net.IPAddress.Parse(normalized))))
            {
                bannedSet.Add(normalized);
            }
        }

        var chunks = AssignBanChunks(prefix + "Ban_", bannedSet, input.PreviousBanChunks);
        foreach (var (name, members) in chunks.OrderBy(c => c.Key, StringComparer.Ordinal))
        {
            plan.BanChunks[name] = members;
            plan.Rules.Add(new FirewallRuleSpec
            {
                Name = name,
                Description = "Addresses banned by TheFirewall after repeated failed logins.",
                Enabled = active,
                RemoteAddresses = string.Join(',', members),
            });
        }

        plan.BlockedEntryCount += bannedSet.Count;

        // ---- Blacklist
        var blacklist = settings.Blacklist.Select(b => IPAddressRange.TryParse(b.Value, out var r) ? (IPAddressRange?)r : null)
            .Where(r => r is not null).Select(r => r!.Value);
        var blacklistRanges = IPAddressRange.Subtract(blacklist, whitelist);
        plan.BlockedEntryCount += AddChunkedRules(plan, prefix + "Blacklist_", blacklistRanges, active, RuleProtocol.Any, string.Empty,
            "Addresses on TheFirewall's blacklist.");

        // ---- Country blocking
        var country = settings.CountryBlocking;
        if (country.Mode != CountryBlockingMode.Off && input.CountryRanges is not null &&
            (country.Countries.Count > 0 || country.Mode == CountryBlockingMode.AllowOnlySelected))
        {
            var target = country.Mode == CountryBlockingMode.BlockSelected
                ? input.CountryRanges.ToList()
                : IPAddressRange.Complement(input.CountryRanges);
            target = IPAddressRange.Subtract(target, protectedRanges);
            var ports = NormalizePorts(country.Ports);
            var description = country.Mode == CountryBlockingMode.BlockSelected
                ? $"Blocks traffic from: {string.Join(", ", country.Countries)}."
                : $"Blocks traffic from every country except: {string.Join(", ", country.Countries)}.";
            if (ports.Length == 0)
            {
                plan.BlockedEntryCount += AddChunkedRules(plan, prefix + "Country_", target, active, RuleProtocol.Any, string.Empty, description);
            }
            else
            {
                plan.BlockedEntryCount += AddChunkedRules(plan, prefix + "CountryTcp_", target, active, RuleProtocol.Tcp, ports, description);
                AddChunkedRules(plan, prefix + "CountryUdp_", target, active, RuleProtocol.Udp, ports, description);
            }
        }

        // ---- Threat feeds
        foreach (var feed in settings.ThreatFeeds.Where(f => f.Enabled))
        {
            if (!input.FeedRanges.TryGetValue(feed.Id, out var feedRanges) || feedRanges.Count == 0)
            {
                continue;
            }

            var target = IPAddressRange.Subtract(feedRanges, protectedRanges);
            plan.BlockedEntryCount += AddChunkedRules(plan, $"{prefix}Feed_{SanitizeId(feed.Id)}_", target, active, RuleProtocol.Any, string.Empty,
                $"Threat feed: {feed.Name}");
        }

        // ---- Optional allow rule for whitelisted addresses
        if (settings.General.WhitelistOpensAllPorts && whitelist.Count > 0)
        {
            AddChunkedRules(plan, prefix + "Whitelist_", IPAddressRange.Merge(whitelist), true, RuleProtocol.Any, string.Empty,
                "Addresses on TheFirewall's whitelist (all ports allowed).", RuleAction.Allow);
        }

        // ---- Custom rules
        foreach (var rule in settings.CustomRules)
        {
            plan.Rules.Add(ToSpec(prefix, rule));
        }

        return plan;
    }

    public static FirewallRuleSpec ToSpec(string prefix, CustomFirewallRule rule)
    {
        bool portsAllowed = rule.Protocol is RuleProtocol.Tcp or RuleProtocol.Udp;
        var addresses = IPUtility.ParseList(rule.RemoteAddresses);
        var keywords = rule.RemoteAddresses.Split([',', ';', '\n', '\r', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(IsAddressKeyword);
        var remote = string.Join(',', IPAddressRange.Merge(addresses).Select(a => a.ToFirewallString()).Concat(keywords));
        return new FirewallRuleSpec
        {
            Name = $"{SanitizePrefix(prefix)}Rule_{SanitizeId(rule.Id)}",
            Description = string.IsNullOrWhiteSpace(rule.Description) ? rule.Name : $"{rule.Name}: {rule.Description}",
            Enabled = rule.Enabled,
            Action = rule.Action,
            Direction = rule.Direction,
            Protocol = rule.Protocol,
            LocalPorts = portsAllowed ? NormalizePorts(rule.LocalPorts) : string.Empty,
            RemotePorts = portsAllowed ? NormalizePorts(rule.RemotePorts) : string.Empty,
            RemoteAddresses = remote,
            ProgramPath = rule.ProgramPath.Trim(),
            Profiles = rule.Profiles == RuleProfiles.None ? RuleProfiles.All : rule.Profiles,
        };
    }

    /// <summary>Windows Firewall address keywords that may be used in custom rules.</summary>
    public static bool IsAddressKeyword(string value) =>
        value.Equals("LocalSubnet", StringComparison.OrdinalIgnoreCase) || value.Equals("DNS", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("DHCP", StringComparison.OrdinalIgnoreCase) || value.Equals("WINS", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("DefaultGateway", StringComparison.OrdinalIgnoreCase) || value.Equals("Internet", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("Intranet", StringComparison.OrdinalIgnoreCase);

    /// <summary>Validates and normalises a port list such as "80, 443, 8000-8100". Returns empty for "any".</summary>
    public static string NormalizePorts(string? ports) => TryNormalizePorts(ports, out var normalized, out _) ? normalized : string.Empty;

    public static bool TryNormalizePorts(string? ports, out string normalized, out string? error)
    {
        normalized = string.Empty;
        error = null;
        if (string.IsNullOrWhiteSpace(ports) || ports.Trim() is "*" or "any" or "Any")
        {
            return true;
        }

        var parts = new List<string>();
        foreach (var raw in ports.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var range = raw.Split('-', StringSplitOptions.TrimEntries);
            if (range.Length is < 1 or > 2 || !range.All(p => int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out int n) && n is >= 1 and <= 65535))
            {
                error = $"'{raw}' is not a valid port or port range (1-65535).";
                return false;
            }

            if (range.Length == 2 && int.Parse(range[0], CultureInfo.InvariantCulture) > int.Parse(range[1], CultureInfo.InvariantCulture))
            {
                error = $"'{raw}': the first port must not be larger than the second.";
                return false;
            }

            parts.Add(string.Join('-', range));
        }

        normalized = string.Join(',', parts.Distinct());
        return true;
    }

    public static string SanitizePrefix(string? prefix)
    {
        var clean = string.Concat((prefix ?? string.Empty).Where(c => char.IsAsciiLetterOrDigit(c) || c == '_'));
        return clean.Length == 0 ? "TheFirewall_" : clean;
    }

    private static string SanitizeId(string id) => string.Concat(id.Where(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-'));

    private static int AddChunkedRules(FirewallPlan plan, string namePrefix, IReadOnlyList<IPAddressRange> ranges, bool enabled,
        RuleProtocol protocol, string localPorts, string description, RuleAction action = RuleAction.Block)
    {
        int index = 0;
        for (int i = 0; i < ranges.Count; i += MaxAddressesPerRule)
        {
            var slice = ranges.Skip(i).Take(MaxAddressesPerRule).Select(r => r.ToFirewallString());
            plan.Rules.Add(new FirewallRuleSpec
            {
                Name = namePrefix + index.ToString("D4", CultureInfo.InvariantCulture),
                Description = description,
                Enabled = enabled,
                Action = action,
                Protocol = protocol,
                LocalPorts = localPorts,
                RemoteAddresses = string.Join(',', slice),
            });
            index++;
        }

        return ranges.Count;
    }

    /// <summary>
    /// Keeps previously assigned addresses in their rule, removes unbanned ones and fills gaps with new ones,
    /// so a single ban or unban only rewrites a single firewall rule.
    /// </summary>
    internal static Dictionary<string, List<string>> AssignBanChunks(string namePrefix, HashSet<string> banned,
        IReadOnlyDictionary<string, List<string>>? previous)
    {
        var chunks = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var assigned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (previous is not null)
        {
            foreach (var (name, members) in previous)
            {
                if (!name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var kept = members.Where(m => banned.Contains(m) && assigned.Add(m)).ToList();
                if (kept.Count > 0)
                {
                    chunks[name] = kept;
                }
            }
        }

        var pending = banned.Where(b => !assigned.Contains(b)).OrderBy(ParseForSort).ToList();
        int pendingIndex = 0;

        foreach (var chunk in chunks.Values)
        {
            while (chunk.Count < MaxAddressesPerRule && pendingIndex < pending.Count)
            {
                chunk.Add(pending[pendingIndex++]);
            }
        }

        int nextIndex = 0;
        while (pendingIndex < pending.Count)
        {
            string name;
            do
            {
                name = namePrefix + nextIndex.ToString("D4", CultureInfo.InvariantCulture);
                nextIndex++;
            }
            while (chunks.ContainsKey(name));

            var chunk = pending.Skip(pendingIndex).Take(MaxAddressesPerRule).ToList();
            pendingIndex += chunk.Count;
            chunks[name] = chunk;
        }

        return chunks;
    }

    private static (AddressFamily, UInt128) ParseForSort(string ip)
    {
        var range = IPAddressRange.Parse(ip);
        return (range.Family, range.Start);
    }
}
