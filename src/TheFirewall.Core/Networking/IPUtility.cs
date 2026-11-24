using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace TheFirewall.Core.Networking;

public static class IPUtility
{
    private static readonly IPAddressRange[] InternalRanges =
    [
        IPAddressRange.Parse("0.0.0.0/8"),
        IPAddressRange.Parse("10.0.0.0/8"),
        IPAddressRange.Parse("100.64.0.0/10"),
        IPAddressRange.Parse("127.0.0.0/8"),
        IPAddressRange.Parse("169.254.0.0/16"),
        IPAddressRange.Parse("172.16.0.0/12"),
        IPAddressRange.Parse("192.0.0.0/24"),
        IPAddressRange.Parse("192.168.0.0/16"),
        IPAddressRange.Parse("198.18.0.0/15"),
        IPAddressRange.Parse("224.0.0.0/3"),
        IPAddressRange.Parse("::/127"),
        IPAddressRange.Parse("fc00::/7"),
        IPAddressRange.Parse("fe80::/10"),
        IPAddressRange.Parse("ff00::/8"),
    ];

    /// <summary>Private, loopback, link-local, carrier-grade NAT, multicast and reserved ranges.</summary>
    public static IReadOnlyList<IPAddressRange> InternalAddressRanges => InternalRanges;

    /// <summary>Maps IPv4-mapped IPv6 addresses to IPv4 and strips scope ids.</summary>
    public static IPAddress Normalize(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv4MappedToIPv6)
            {
                return address.MapToIPv4();
            }

            if (address.ScopeId != 0)
            {
                return new IPAddress(address.GetAddressBytes());
            }
        }

        return address;
    }

    /// <summary>
    /// Parses an IP address the way it typically appears in logs: tolerates surrounding brackets,
    /// ports (1.2.3.4:5678, [::1]:22), zone ids and IPv4-mapped IPv6 notation.
    /// </summary>
    public static bool TryParseAddress([NotNullWhen(true)] string? text, [NotNullWhen(true)] out IPAddress? address)
    {
        address = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var span = text.AsSpan().Trim().Trim("\"'");
        if (span.Length == 0 || span.Length > 64)
        {
            return false;
        }

        // [v6]:port or [v6]
        if (span[0] == '[')
        {
            int close = span.IndexOf(']');
            if (close < 0)
            {
                return false;
            }

            span = span[1..close];
        }
        else
        {
            int firstColon = span.IndexOf(':');
            int lastColon = span.LastIndexOf(':');

            // a.b.c.d:port (exactly one colon) -> drop the port
            if (firstColon > 0 && firstColon == lastColon)
            {
                span = span[..firstColon];
            }
        }

        int percent = span.IndexOf('%');
        if (percent > 0)
        {
            span = span[..percent];
        }

        // Only accept characters that can be part of an IP address, which avoids IPAddress.Parse
        // accepting odd legacy forms such as "1" or "0x7f.1".
        foreach (char c in span)
        {
            if (!(char.IsAsciiHexDigit(c) || c == '.' || c == ':'))
            {
                return false;
            }
        }

        if (!span.Contains(':') && span.Count('.') != 3)
        {
            return false;
        }

        if (!IPAddress.TryParse(span, out var parsed))
        {
            return false;
        }

        address = Normalize(parsed);
        return true;
    }

    /// <summary>Returns the canonical text form of an address, or null when it is not a valid IP.</summary>
    public static string? NormalizeText(string? text) => TryParseAddress(text, out var ip) ? ip.ToString() : null;

    public static bool IsInternal(IPAddress address)
    {
        address = Normalize(address);
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.Broadcast))
        {
            return true;
        }

        foreach (var range in InternalRanges)
        {
            if (range.Contains(address))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Parses a comma, semicolon or newline separated list of addresses/ranges, collecting invalid entries.</summary>
    public static List<IPAddressRange> ParseList(string? text, List<string>? invalid = null)
    {
        var result = new List<IPAddressRange>();
        if (string.IsNullOrWhiteSpace(text))
        {
            return result;
        }

        foreach (var raw in text.Split([',', ';', '\n', '\r', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (IPAddressRange.TryParse(raw, out var range))
            {
                result.Add(range);
            }
            else
            {
                invalid?.Add(raw);
            }
        }

        return result;
    }
}
