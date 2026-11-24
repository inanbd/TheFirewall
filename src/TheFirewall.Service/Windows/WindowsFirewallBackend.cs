using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Firewall;

namespace TheFirewall.Service.Windows;

/// <summary>Manages rules in Windows Defender Firewall through its COM API (HNetCfg.FwPolicy2).</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsFirewallBackend : IFirewallBackend
{
    private readonly ILogger logger;
    private readonly object sync = new();
    private readonly INetFwPolicy2 policy;

    public WindowsFirewallBackend(ILogger logger)
    {
        this.logger = logger;
        var type = Type.GetTypeFromCLSID(new Guid(NetFw.PolicyClsid), throwOnError: true)!;
        policy = (INetFwPolicy2)(Activator.CreateInstance(type) ?? throw new InvalidOperationException("Unable to create the Windows Firewall policy object."));
    }

    public string Name => "Windows Defender Firewall";

    public IReadOnlyList<string> GetRuleNames(string prefix)
    {
        var names = new List<string>();
        lock (sync)
        {
            var rules = policy.Rules;
            var enumerator = rules.GetEnumeratorVariant();
            var buffer = new object[64];
            IntPtr fetchedPointer = Marshal.AllocCoTaskMem(sizeof(int));
            try
            {
                while (true)
                {
                    Marshal.WriteInt32(fetchedPointer, 0);
                    enumerator.Next(buffer.Length, buffer, fetchedPointer);
                    int fetched = Marshal.ReadInt32(fetchedPointer);
                    for (int i = 0; i < fetched; i++)
                    {
                        if (buffer[i] is INetFwRule rule)
                        {
                            try
                            {
                                var name = rule.Name;
                                if (name is not null && name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                                {
                                    names.Add(name);
                                }
                            }
                            finally
                            {
                                Marshal.ReleaseComObject(rule);
                            }
                        }

                        buffer[i] = null!;
                    }

                    if (fetched < buffer.Length)
                    {
                        break;
                    }
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(fetchedPointer);
                Marshal.ReleaseComObject(enumerator);
                Marshal.ReleaseComObject(rules);
            }
        }

        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public void SetRule(FirewallRuleSpec spec)
    {
        lock (sync)
        {
            var rules = policy.Rules;
            try
            {
                var existing = TryGetRule(rules, spec.Name);
                if (existing is not null)
                {
                    try
                    {
                        if (CanUpdateInPlace(existing, spec))
                        {
                            ApplyMutableProperties(existing, spec);
                            return;
                        }
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(existing);
                    }

                    // Windows may hold several rules with the same name; remove them all before re-creating.
                    RemoveAll(rules, spec.Name);
                }

                var rule = CreateRule();
                try
                {
                    rule.Name = spec.Name;
                    rule.Direction = spec.Direction == RuleDirection.Outbound ? NetFw.DirectionOutbound : NetFw.DirectionInbound;
                    rule.Action = spec.Action == RuleAction.Allow ? NetFw.ActionAllow : NetFw.ActionBlock;
                    rule.Protocol = ToProtocol(spec.Protocol);
                    if (spec.Protocol is RuleProtocol.Tcp or RuleProtocol.Udp)
                    {
                        if (!string.IsNullOrWhiteSpace(spec.LocalPorts))
                        {
                            rule.LocalPorts = spec.LocalPorts;
                        }

                        if (!string.IsNullOrWhiteSpace(spec.RemotePorts))
                        {
                            rule.RemotePorts = spec.RemotePorts;
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(spec.ProgramPath))
                    {
                        rule.ApplicationName = spec.ProgramPath;
                    }

                    rule.InterfaceTypes = "All";
                    ApplyMutableProperties(rule, spec);
                    rules.Add(rule);
                }
                finally
                {
                    Marshal.ReleaseComObject(rule);
                }
            }
            finally
            {
                Marshal.ReleaseComObject(rules);
            }
        }
    }

    public void DeleteRule(string name)
    {
        lock (sync)
        {
            var rules = policy.Rules;
            try
            {
                RemoveAll(rules, name);
            }
            finally
            {
                Marshal.ReleaseComObject(rules);
            }
        }
    }

    public FirewallProfileState GetProfileState()
    {
        lock (sync)
        {
            try
            {
                return new FirewallProfileState
                {
                    DomainEnabled = policy.get_FirewallEnabled(NetFw.ProfileDomain),
                    PrivateEnabled = policy.get_FirewallEnabled(NetFw.ProfilePrivate),
                    PublicEnabled = policy.get_FirewallEnabled(NetFw.ProfilePublic),
                };
            }
            catch (Exception ex) when (ex is COMException or UnauthorizedAccessException)
            {
                logger.LogWarning(ex, "Unable to read the Windows Firewall profile state");
                return new FirewallProfileState { Available = false, Error = ex.Message };
            }
        }
    }

    private static void ApplyMutableProperties(INetFwRule rule, FirewallRuleSpec spec)
    {
        rule.Description = Truncate(spec.Description, 1000);
        rule.Grouping = spec.Grouping;
        rule.Profiles = spec.Profiles == RuleProfiles.All || spec.Profiles == RuleProfiles.None ? NetFw.ProfileAll : (int)spec.Profiles;
        rule.RemoteAddresses = string.IsNullOrWhiteSpace(spec.RemoteAddresses) ? "*" : spec.RemoteAddresses;
        rule.Enabled = spec.Enabled;
    }

    private static bool CanUpdateInPlace(INetFwRule rule, FirewallRuleSpec spec)
    {
        bool portsWanted = spec.Protocol is RuleProtocol.Tcp or RuleProtocol.Udp;
        return rule.Direction == (spec.Direction == RuleDirection.Outbound ? NetFw.DirectionOutbound : NetFw.DirectionInbound) &&
               rule.Action == (spec.Action == RuleAction.Allow ? NetFw.ActionAllow : NetFw.ActionBlock) &&
               rule.Protocol == ToProtocol(spec.Protocol) &&
               SamePorts(rule.LocalPorts, portsWanted ? spec.LocalPorts : string.Empty) &&
               SamePorts(rule.RemotePorts, portsWanted ? spec.RemotePorts : string.Empty) &&
               string.Equals(rule.ApplicationName ?? string.Empty, spec.ProgramPath ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    private static bool SamePorts(string? actual, string? wanted)
    {
        static string Normalize(string? value) => string.IsNullOrWhiteSpace(value) || value == "*" ? string.Empty : value.Replace(" ", string.Empty, StringComparison.Ordinal);
        return string.Equals(Normalize(actual), Normalize(wanted), StringComparison.OrdinalIgnoreCase);
    }

    private static INetFwRule? TryGetRule(INetFwRules rules, string name)
    {
        try
        {
            return rules.Item(name);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (COMException)
        {
            return null;
        }
    }

    private static void RemoveAll(INetFwRules rules, string name)
    {
        // Remove deletes one rule per call; loop in case duplicates exist.
        for (int i = 0; i < 100; i++)
        {
            var existing = TryGetRule(rules, name);
            if (existing is null)
            {
                return;
            }

            Marshal.ReleaseComObject(existing);
            rules.Remove(name);
        }
    }

    private static INetFwRule CreateRule()
    {
        var type = Type.GetTypeFromCLSID(new Guid(NetFw.RuleClsid), throwOnError: true)!;
        return (INetFwRule)(Activator.CreateInstance(type) ?? throw new InvalidOperationException("Unable to create a Windows Firewall rule object."));
    }

    private static int ToProtocol(RuleProtocol protocol) => protocol switch
    {
        RuleProtocol.Tcp => NetFw.ProtocolTcp,
        RuleProtocol.Udp => NetFw.ProtocolUdp,
        RuleProtocol.IcmpV4 => NetFw.ProtocolIcmpV4,
        RuleProtocol.IcmpV6 => NetFw.ProtocolIcmpV6,
        _ => NetFw.ProtocolAny,
    };

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}
