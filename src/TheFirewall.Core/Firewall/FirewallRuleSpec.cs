using System.Security.Cryptography;
using System.Text;
using TheFirewall.Core.Configuration;

namespace TheFirewall.Core.Firewall;

/// <summary>A Windows Firewall rule as TheFirewall wants it to exist.</summary>
public sealed record FirewallRuleSpec
{
    public required string Name { get; init; }

    public string Description { get; init; } = string.Empty;

    /// <summary>Optional rule group shown in the Windows Firewall console.</summary>
    public string Grouping { get; init; } = "TheFirewall";

    public bool Enabled { get; init; } = true;

    public RuleAction Action { get; init; } = RuleAction.Block;

    public RuleDirection Direction { get; init; } = RuleDirection.Inbound;

    public RuleProtocol Protocol { get; init; } = RuleProtocol.Any;

    public string LocalPorts { get; init; } = string.Empty;

    public string RemotePorts { get; init; } = string.Empty;

    /// <summary>Comma separated remote addresses; empty means any.</summary>
    public string RemoteAddresses { get; init; } = string.Empty;

    public string ProgramPath { get; init; } = string.Empty;

    public RuleProfiles Profiles { get; init; } = RuleProfiles.All;

    /// <summary>Fingerprint of every property, used to skip rules that did not change.</summary>
    public string ComputeHash()
    {
        var text = string.Join('\u001f', Name, Description, Grouping, Enabled, Action, Direction, Protocol, LocalPorts, RemotePorts,
            RemoteAddresses, ProgramPath, (int)Profiles);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..32];
    }
}

/// <summary>Applies rule specifications to a firewall.</summary>
public interface IFirewallBackend
{
    /// <summary>Human readable name, e.g. "Windows Defender Firewall".</summary>
    string Name { get; }

    /// <summary>Names of existing rules that start with the prefix.</summary>
    IReadOnlyList<string> GetRuleNames(string prefix);

    /// <summary>Creates the rule or replaces all of its properties.</summary>
    void SetRule(FirewallRuleSpec rule);

    void DeleteRule(string name);

    /// <summary>Reports which firewall profiles are switched on, for warnings in the UI.</summary>
    FirewallProfileState GetProfileState();
}

public sealed class FirewallProfileState
{
    public bool DomainEnabled { get; set; } = true;

    public bool PrivateEnabled { get; set; } = true;

    public bool PublicEnabled { get; set; } = true;

    public bool Available { get; set; } = true;

    public string? Error { get; set; }
}

/// <summary>A firewall that only remembers rules in memory; used for tests and demo mode.</summary>
public sealed class InMemoryFirewallBackend : IFirewallBackend
{
    private readonly Dictionary<string, FirewallRuleSpec> rules = new(StringComparer.OrdinalIgnoreCase);

    public string Name => "In-memory firewall";

    public IReadOnlyDictionary<string, FirewallRuleSpec> Rules
    {
        get
        {
            lock (rules)
            {
                return new Dictionary<string, FirewallRuleSpec>(rules, StringComparer.OrdinalIgnoreCase);
            }
        }
    }

    public int SetCount { get; private set; }

    public IReadOnlyList<string> GetRuleNames(string prefix)
    {
        lock (rules)
        {
            return rules.Keys.Where(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToList();
        }
    }

    public void SetRule(FirewallRuleSpec rule)
    {
        lock (rules)
        {
            rules[rule.Name] = rule;
            SetCount++;
        }
    }

    public void DeleteRule(string name)
    {
        lock (rules)
        {
            rules.Remove(name);
        }
    }

    public FirewallProfileState GetProfileState() => new();
}
