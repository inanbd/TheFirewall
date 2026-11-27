using System.Globalization;
using System.Net;
using System.Text.Json.Serialization;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Firewall;

namespace TheFirewall.Core.Ports;

[JsonConverter(typeof(JsonStringEnumConverter<PortExposure>))]
public enum PortExposure
{
    /// <summary>Listening on a loopback address: only programs on this computer can connect.</summary>
    LocalOnly,

    /// <summary>Anyone on the network or the internet can connect.</summary>
    Open,

    /// <summary>Only some addresses can connect.</summary>
    OpenToSome,

    /// <summary>Windows Firewall blocks incoming connections.</summary>
    Blocked,

    Unknown,
}

/// <summary>A port a program on this computer is listening on (one entry per protocol, port and process).</summary>
public sealed class ListeningPort
{
    /// <summary>"TCP" or "UDP".</summary>
    public string Protocol { get; set; } = "TCP";

    public int Port { get; set; }

    /// <summary>Local addresses the program listens on, e.g. "0.0.0.0" and "::".</summary>
    public List<string> Addresses { get; set; } = [];

    public int ProcessId { get; set; }

    public string? ProcessName { get; set; }

    /// <summary>Full path of the program ("System" for the Windows kernel), null when it could not be read.</summary>
    public string? ProcessPath { get; set; }

    /// <summary>SID of the account the program runs as (e.g. S-1-5-18 for SYSTEM), null when unknown.</summary>
    public string? UserSid { get; set; }

    /// <summary>Name of that account, e.g. "NT AUTHORITY\SYSTEM".</summary>
    public string? UserName { get; set; }

    /// <summary>Short names of the Windows services hosted by the process.</summary>
    public List<string> ServiceNames { get; set; } = [];

    /// <summary>Display names of those services.</summary>
    public List<string> Services { get; set; } = [];

    /// <summary>What the port is commonly used for, e.g. "Remote Desktop".</summary>
    public string? KnownName { get; set; }

    public PortExposure Exposure { get; set; } = PortExposure.Unknown;

    /// <summary>Plain-language explanation of <see cref="Exposure"/>.</summary>
    public string ExposureText { get; set; } = string.Empty;

    /// <summary>The Ports page entry that manages this port, if any.</summary>
    public string? ManagedPortId { get; set; }
}

public sealed class ListeningPortsResponse
{
    public List<ListeningPort> Ports { get; set; } = [];

    public string? Error { get; set; }
}

/// <summary>An existing inbound Windows Firewall rule, reduced to what decides whether a port is reachable.</summary>
public sealed class FirewallRuleInfo
{
    public string Name { get; set; } = string.Empty;

    public bool Enabled { get; set; }

    public bool Allow { get; set; }

    /// <summary>IANA protocol number; 256 means any.</summary>
    public int Protocol { get; set; } = 256;

    public string LocalPorts { get; set; } = string.Empty;

    public string RemoteAddresses { get; set; } = string.Empty;

    public string ApplicationName { get; set; } = string.Empty;

    public string ServiceName { get; set; } = string.Empty;

    /// <summary>Windows Firewall profile bitmask (1 domain, 2 private, 4 public).</summary>
    public int Profiles { get; set; } = 0x7FFFFFFF;

    /// <summary>Package SID of the Microsoft Store app the rule is limited to; empty for ordinary rules.</summary>
    public string AppPackageId { get; set; } = string.Empty;

    /// <summary>SID of the rule's owner: the rule then only applies to programs running as that account.</summary>
    public string LocalUserOwner { get; set; } = string.Empty;

    /// <summary>Display name of <see cref="LocalUserOwner"/>.</summary>
    public string LocalUserOwnerName { get; set; } = string.Empty;

    /// <summary>The rule only applies to the users in this list (SDDL); such rules are not counted.</summary>
    public string LocalUserAuthorizedList { get; set; } = string.Empty;
}

/// <summary>Windows Firewall settings for the network profiles that are active right now.</summary>
public sealed class FirewallPolicyInfo
{
    public int CurrentProfiles { get; set; } = 4;

    /// <summary>False when Windows Firewall is turned off for an active profile.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>True when incoming connections that no rule allows are blocked (the Windows default).</summary>
    public bool DefaultInboundBlock { get; set; } = true;

    /// <summary>"Block all incoming connections, including those in the list of allowed apps".</summary>
    public bool BlockAllInbound { get; set; }
}

/// <summary>Reads listening ports and Windows Firewall rules (implemented by the Windows service).</summary>
public interface IPortInspector
{
    IReadOnlyList<ListeningPort> GetListeningPorts();

    IReadOnlyList<FirewallRuleInfo> GetInboundRules();

    FirewallPolicyInfo GetPolicy();
}

/// <summary>A common service and its port, for quick-add buttons and naming listening ports.</summary>
public sealed record KnownPort(string Name, RuleProtocol Protocol, string Ports);

public static class PortCatalog
{
    /// <summary>Shown as quick-add buttons on the Ports page.</summary>
    public static IReadOnlyList<KnownPort> Common { get; } =
    [
        new("Remote Desktop", RuleProtocol.Any, "3389"),
        new("SSH", RuleProtocol.Tcp, "22"),
        new("SQL Server", RuleProtocol.Tcp, "1433"),
        new("Web server", RuleProtocol.Tcp, "80,443"),
        new("FTP", RuleProtocol.Tcp, "21"),
        new("File sharing (SMB)", RuleProtocol.Tcp, "445"),
        new("Remote management (WinRM)", RuleProtocol.Tcp, "5985-5986"),
        new("MySQL", RuleProtocol.Tcp, "3306"),
        new("PostgreSQL", RuleProtocol.Tcp, "5432"),
    ];

    private static readonly Dictionary<int, string> Names = new()
    {
        [20] = "FTP data", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "Mail (SMTP)", [53] = "DNS", [67] = "DHCP", [69] = "TFTP",
        [80] = "Web (HTTP)", [88] = "Kerberos", [110] = "Mail (POP3)", [123] = "Time (NTP)", [135] = "Windows RPC", [137] = "NetBIOS names",
        [138] = "NetBIOS datagrams", [139] = "NetBIOS sessions", [143] = "Mail (IMAP)", [161] = "SNMP", [389] = "LDAP", [443] = "Web (HTTPS)",
        [445] = "File sharing (SMB)", [464] = "Kerberos passwords", [465] = "Mail (SMTPS)", [500] = "IPsec (IKE)", [587] = "Mail submission",
        [636] = "LDAPS", [990] = "FTPS", [993] = "Mail (IMAPS)", [995] = "Mail (POP3S)", [1194] = "OpenVPN", [1433] = "SQL Server",
        [1434] = "SQL Server Browser", [1701] = "L2TP VPN", [1723] = "PPTP VPN", [1900] = "SSDP discovery", [3268] = "Global Catalog",
        [3269] = "Global Catalog (SSL)", [3306] = "MySQL", [3389] = "Remote Desktop", [3702] = "WS-Discovery", [4500] = "IPsec NAT-T",
        [5353] = "mDNS", [5355] = "LLMNR", [5432] = "PostgreSQL", [5900] = "VNC", [5985] = "WinRM (HTTP)", [5986] = "WinRM (HTTPS)",
        [6379] = "Redis", [8080] = "Web (HTTP alternate)", [8443] = "Web (HTTPS alternate)", [9389] = "AD Web Services",
        [11211] = "Memcached", [27017] = "MongoDB", [47001] = "WinRM listener",
    };

    public static string? GetName(int port) => Names.GetValueOrDefault(port);
}

/// <summary>Works out whether a listening port can be reached from the network.</summary>
public static class PortReachability
{
    public static void Evaluate(ListeningPort port, IReadOnlyList<FirewallRuleInfo> rules, FirewallPolicyInfo policy,
        FirewallSettings settings, DateTimeOffset now, TimeZoneInfo zone)
    {
        var protocol = port.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) ? RuleProtocol.Udp : RuleProtocol.Tcp;
        var managed = settings.Ports.FirstOrDefault(p => Covers(p, protocol, port.Port));
        port.ManagedPortId = managed?.Id;

        if (port.Addresses.Count > 0 && port.Addresses.All(IsLoopback))
        {
            Set(port, PortExposure.LocalOnly, "Only programs on this computer can connect.");
            return;
        }

        if (managed is not null)
        {
            var state = PortPolicy.Evaluate(managed, now, zone);
            var until = state.NextChangeUtc is { } next ? " until " + TimeZoneInfo.ConvertTime(next, zone).ToString("ddd HH:mm", CultureInfo.InvariantCulture) : string.Empty;
            switch (state.Access)
            {
                case PortAccess.Everyone:
                    Set(port, PortExposure.Open, state.Reason == PortStateReason.TemporarilyOpen
                        ? $"Temporarily open to everyone{until} (\"{managed.Name}\" on the Ports page)."
                        : $"Open to everyone{until} (\"{managed.Name}\" on the Ports page).");
                    return;
                case PortAccess.Restricted:
                    Set(port, PortExposure.OpenToSome, $"Only some addresses may connect{until} (\"{managed.Name}\" on the Ports page).");
                    return;
                default:
                    Set(port, PortExposure.Blocked, state.Reason == PortStateReason.OutsideSchedule
                        ? $"Closed outside its open hours{until} (\"{managed.Name}\" on the Ports page)."
                        : $"Closed by \"{managed.Name}\" on the Ports page.");
                    return;
            }
        }

        if (!policy.Enabled)
        {
            Set(port, PortExposure.Open, "Open: Windows Firewall is turned off.");
            return;
        }

        if (policy.BlockAllInbound)
        {
            Set(port, PortExposure.Blocked, "Blocked: Windows Firewall blocks all incoming connections.");
            return;
        }

        var prefix = FirewallPlanner.SanitizePrefix(settings.General.FirewallRulePrefix);
        var matching = rules.Where(r => r.Enabled && AppliesTo(r, port, protocol, policy.CurrentProfiles) &&
                                        !r.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToList();

        var blocking = matching.FirstOrDefault(r => !r.Allow && IsAnyAddress(r.RemoteAddresses));
        if (blocking is not null)
        {
            Set(port, PortExposure.Blocked, $"Blocked by the Windows Firewall rule \"{blocking.Name}\".");
            return;
        }

        var allowAll = matching.FirstOrDefault(r => r.Allow && IsAnyAddress(r.RemoteAddresses));
        if (allowAll is not null)
        {
            Set(port, PortExposure.Open, $"Open to everyone: allowed by the Windows Firewall rule \"{allowAll.Name}\"{OwnerNote(allowAll)}.");
            return;
        }

        var allowSome = matching.FirstOrDefault(r => r.Allow);
        if (allowSome is not null)
        {
            Set(port, PortExposure.OpenToSome, $"Some addresses ({allowSome.RemoteAddresses}) may connect: allowed by \"{allowSome.Name}\"{OwnerNote(allowSome)}.");
            return;
        }

        if (!policy.DefaultInboundBlock)
        {
            Set(port, PortExposure.Open, "Open: Windows Firewall allows incoming connections that no rule blocks.");
            return;
        }

        Set(port, PortExposure.Blocked, "Blocked: no Windows Firewall rule allows incoming connections to it.");
    }

    /// <summary>True when the Ports page entry covers this protocol and port.</summary>
    public static bool Covers(PortRule rule, RuleProtocol protocol, int port) =>
        (rule.Protocol == RuleProtocol.Any || rule.Protocol == protocol) && PortListContains(rule.Ports, port);

    /// <summary>True when a Windows Firewall port list ("80,443,8000-8100", "*" or empty for any) includes the port.</summary>
    public static bool PortListContains(string? list, int port)
    {
        if (string.IsNullOrWhiteSpace(list) || list.Trim() is "*" or "Any")
        {
            return true;
        }

        foreach (var token in list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = token.Split('-', StringSplitOptions.TrimEntries);
            if (parts.Length == 1 && int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out int single) && single == port)
            {
                return true;
            }

            if (parts.Length == 2 && int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out int low) &&
                int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int high) && port >= low && port <= high)
            {
                return true;
            }

            // Keywords such as "RPC" or "IPHTTPS" match special dynamic ports only; they are not counted here.
        }

        return false;
    }

    private static bool AppliesTo(FirewallRuleInfo rule, ListeningPort port, RuleProtocol protocol, int currentProfiles)
    {
        if ((rule.Profiles & currentProfiles) == 0)
        {
            return false;
        }

        // Rules for a Microsoft Store app only apply to that app's processes, never to services and desktop programs.
        if (!IsAny(rule.AppPackageId))
        {
            return false;
        }

        // A rule with an owner only applies to programs running as that account (e.g. "Windows Feature Experience
        // Pack" on Windows Server 2025 allows everything, but only for programs running as SYSTEM).
        if (!IsAny(rule.LocalUserOwner) && !string.Equals(rule.LocalUserOwner.Trim(), port.UserSid, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Rules limited to a list of users cannot be checked here; they are not counted.
        if (!IsAny(rule.LocalUserAuthorizedList))
        {
            return false;
        }

        bool protocolMatches = rule.Protocol == 256 || (protocol == RuleProtocol.Tcp ? rule.Protocol == 6 : rule.Protocol == 17);
        if (!protocolMatches || !PortListContains(rule.LocalPorts, port.Port))
        {
            return false;
        }

        if (!IsAny(rule.ApplicationName))
        {
            var app = Environment.ExpandEnvironmentVariables(rule.ApplicationName.Trim());
            if (port.ProcessPath is null || !string.Equals(Path.GetFullPathSafe(app), Path.GetFullPathSafe(port.ProcessPath), StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        if (!IsAny(rule.ServiceName) && !port.ServiceNames.Contains(rule.ServiceName.Trim(), StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private static bool IsAny(string? value) => string.IsNullOrWhiteSpace(value) || value.Trim() == "*";

    private static string OwnerNote(FirewallRuleInfo rule) => IsAny(rule.LocalUserOwner)
        ? string.Empty
        : $", which applies to programs running as {(string.IsNullOrWhiteSpace(rule.LocalUserOwnerName) ? rule.LocalUserOwner : rule.LocalUserOwnerName)}";

    private static bool IsAnyAddress(string? value) => IsAny(value) || value!.Trim().Equals("Any", StringComparison.OrdinalIgnoreCase);

    private static bool IsLoopback(string address) => IPAddress.TryParse(address, out var ip) && IPAddress.IsLoopback(ip);

    private static void Set(ListeningPort port, PortExposure exposure, string text)
    {
        port.Exposure = exposure;
        port.ExposureText = text;
    }

    private static class Path
    {
        /// <summary>Normalises a program path for comparison ("System" stays as is).</summary>
        public static string GetFullPathSafe(string path)
        {
            try
            {
                return System.IO.Path.IsPathFullyQualified(path) ? System.IO.Path.GetFullPath(path) : path;
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or System.IO.PathTooLongException)
            {
                return path;
            }
        }
    }
}
