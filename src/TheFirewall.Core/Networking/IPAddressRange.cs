using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace TheFirewall.Core.Networking;

/// <summary>
/// An inclusive range of IP addresses of a single address family. Supports single addresses,
/// CIDR blocks (<c>10.0.0.0/8</c>), explicit ranges (<c>1.2.3.4-1.2.3.10</c>) and
/// wildcards (<c>192.168.1.*</c>).
/// </summary>
public readonly record struct IPAddressRange : IComparable<IPAddressRange>
{
    private static readonly UInt128 MaxV4 = uint.MaxValue;

    public IPAddressRange(AddressFamily family, UInt128 start, UInt128 end)
    {
        if (family is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            throw new ArgumentOutOfRangeException(nameof(family));
        }

        if (start > end)
        {
            (start, end) = (end, start);
        }

        if (family == AddressFamily.InterNetwork && end > MaxV4)
        {
            throw new ArgumentOutOfRangeException(nameof(end));
        }

        Family = family;
        Start = start;
        End = end;
    }

    public AddressFamily Family { get; }

    public UInt128 Start { get; }

    public UInt128 End { get; }

    public bool IsIPv4 => Family == AddressFamily.InterNetwork;

    public bool IsSingleAddress => Start == End;

    /// <summary>Number of addresses in the range minus one (avoids overflow for the full IPv6 space).</summary>
    public UInt128 SizeMinusOne => End - Start;

    public IPAddress StartAddress => ToAddress(Family, Start);

    public IPAddress EndAddress => ToAddress(Family, End);

    public static IPAddressRange FullV4 => new(AddressFamily.InterNetwork, 0, MaxV4);

    public static IPAddressRange FullV6 => new(AddressFamily.InterNetworkV6, 0, UInt128.MaxValue);

    public static IPAddressRange FromAddress(IPAddress address)
    {
        address = IPUtility.Normalize(address);
        var value = ToNumber(address);
        return new IPAddressRange(address.AddressFamily, value, value);
    }

    public static IPAddressRange FromCidr(IPAddress network, int prefixLength)
    {
        network = IPUtility.Normalize(network);
        int bits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefixLength < 0 || prefixLength > bits)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixLength));
        }

        UInt128 value = ToNumber(network);
        int hostBits = bits - prefixLength;
        UInt128 hostMask = hostBits == 0 ? UInt128.Zero : (hostBits == 128 ? UInt128.MaxValue : (UInt128.One << hostBits) - 1);
        UInt128 start = value & ~hostMask;
        if (bits == 32)
        {
            start &= MaxV4;
        }

        return new IPAddressRange(network.AddressFamily, start, start + hostMask);
    }

    public static IPAddressRange Parse(string text) =>
        TryParse(text, out var range) ? range : throw new FormatException($"'{text}' is not a valid IP address, CIDR block or range.");

    /// <summary>Parses an address, CIDR block, "start-end" range or IPv4 wildcard such as 10.1.*.*.</summary>
    public static bool TryParse([NotNullWhen(true)] string? text, out IPAddressRange range)
    {
        range = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        text = text.Trim();

        // CIDR
        int slash = text.IndexOf('/');
        if (slash > 0)
        {
            var addressPart = text[..slash].Trim();
            var prefixPart = text[(slash + 1)..].Trim();
            if (!IPUtility.TryParseAddress(addressPart, out var network))
            {
                return false;
            }

            int maxBits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out int prefix))
            {
                if (prefix < 0 || prefix > maxBits)
                {
                    return false;
                }

                // An IPv4-mapped IPv6 CIDR (::ffff:1.2.3.0/120) is normalised to IPv4.
                if (addressPart.Contains(':') && network.AddressFamily == AddressFamily.InterNetwork)
                {
                    prefix -= 96;
                    if (prefix < 0)
                    {
                        return false;
                    }
                }

                range = FromCidr(network, prefix);
                return true;
            }

            // Netmask form: 10.0.0.0/255.0.0.0 (this is how Windows Firewall reports addresses).
            if (IPAddress.TryParse(prefixPart, out var mask) && mask.AddressFamily == network.AddressFamily)
            {
                int? maskBits = MaskToPrefix(mask);
                if (maskBits is null)
                {
                    return false;
                }

                range = FromCidr(network, maskBits.Value);
                return true;
            }

            return false;
        }

        // Wildcard IPv4: 10.20.*.*
        if (text.Contains('*'))
        {
            return TryParseWildcard(text, out range);
        }

        // Range: a-b
        int dash = text.IndexOf('-');
        if (dash > 0)
        {
            if (!IPUtility.TryParseAddress(text[..dash].Trim(), out var first) ||
                !IPUtility.TryParseAddress(text[(dash + 1)..].Trim(), out var last) ||
                first.AddressFamily != last.AddressFamily)
            {
                return false;
            }

            range = new IPAddressRange(first.AddressFamily, ToNumber(first), ToNumber(last));
            return true;
        }

        if (IPUtility.TryParseAddress(text, out var single))
        {
            range = FromAddress(single);
            return true;
        }

        return false;
    }

    public bool Contains(IPAddress address)
    {
        address = IPUtility.Normalize(address);
        if (address.AddressFamily != Family)
        {
            return false;
        }

        var value = ToNumber(address);
        return value >= Start && value <= End;
    }

    public bool Contains(IPAddressRange other) => other.Family == Family && other.Start >= Start && other.End <= End;

    public bool Overlaps(IPAddressRange other) => other.Family == Family && other.Start <= End && other.End >= Start;

    /// <summary>
    /// Returns the prefix length when the range is exactly a CIDR block, otherwise null.
    /// </summary>
    public int? GetPrefixLength()
    {
        int bits = IsIPv4 ? 32 : 128;
        UInt128 size = SizeMinusOne;
        if (size == UInt128.MaxValue)
        {
            return Start == 0 ? 0 : null;
        }

        UInt128 count = size + 1;
        if (!UInt128.IsPow2(count))
        {
            return null;
        }

        int hostBits = (int)UInt128.Log2(count);
        if ((Start & size) != 0)
        {
            return null;
        }

        return bits - hostBits;
    }

    /// <summary>Formats the range the way Windows Firewall accepts it: address, CIDR or start-end.</summary>
    public string ToFirewallString()
    {
        if (IsSingleAddress)
        {
            return StartAddress.ToString();
        }

        int? prefix = GetPrefixLength();
        return prefix is not null
            ? string.Create(CultureInfo.InvariantCulture, $"{StartAddress}/{prefix}")
            : string.Create(CultureInfo.InvariantCulture, $"{StartAddress}-{EndAddress}");
    }

    public override string ToString() => ToFirewallString();

    public int CompareTo(IPAddressRange other)
    {
        int c = Family.CompareTo(other.Family);
        if (c != 0)
        {
            return c;
        }

        c = Start.CompareTo(other.Start);
        return c != 0 ? c : End.CompareTo(other.End);
    }

    /// <summary>Sorts and merges overlapping or adjacent ranges.</summary>
    public static List<IPAddressRange> Merge(IEnumerable<IPAddressRange> ranges)
    {
        var sorted = ranges.ToList();
        sorted.Sort();
        var result = new List<IPAddressRange>(sorted.Count);
        foreach (var r in sorted)
        {
            if (result.Count > 0)
            {
                var last = result[^1];
                if (last.Family == r.Family && (last.End == UInt128.MaxValue || r.Start <= last.End + 1))
                {
                    if (r.End > last.End)
                    {
                        result[^1] = new IPAddressRange(last.Family, last.Start, r.End);
                    }

                    continue;
                }
            }

            result.Add(r);
        }

        return result;
    }

    /// <summary>Removes every address in <paramref name="excluded"/> from <paramref name="ranges"/>.</summary>
    public static List<IPAddressRange> Subtract(IEnumerable<IPAddressRange> ranges, IEnumerable<IPAddressRange> excluded)
    {
        var source = Merge(ranges);
        var remove = Merge(excluded);
        if (remove.Count == 0)
        {
            return source;
        }

        var result = new List<IPAddressRange>(source.Count);
        int j = 0;
        foreach (var range in source)
        {
            UInt128 currentStart = range.Start;
            bool exhausted = false;

            // Skip exclusions that are entirely before this range.
            while (j < remove.Count && (remove[j].Family < range.Family ||
                   (remove[j].Family == range.Family && remove[j].End < range.Start)))
            {
                j++;
            }

            int k = j;
            while (k < remove.Count && remove[k].Family == range.Family && remove[k].Start <= range.End)
            {
                var ex = remove[k];
                if (ex.Start > currentStart)
                {
                    result.Add(new IPAddressRange(range.Family, currentStart, ex.Start - 1));
                }

                if (ex.End >= range.End)
                {
                    exhausted = true;
                    break;
                }

                currentStart = UInt128.Max(currentStart, ex.End + 1);
                k++;
            }

            if (!exhausted && currentStart <= range.End)
            {
                result.Add(new IPAddressRange(range.Family, currentStart, range.End));
            }
        }

        return result;
    }

    /// <summary>Returns every address of the given families that is not covered by <paramref name="ranges"/>.</summary>
    public static List<IPAddressRange> Complement(IEnumerable<IPAddressRange> ranges, bool includeIPv4 = true, bool includeIPv6 = true)
    {
        var universe = new List<IPAddressRange>();
        if (includeIPv4)
        {
            universe.Add(FullV4);
        }

        if (includeIPv6)
        {
            universe.Add(FullV6);
        }

        return Subtract(universe, ranges);
    }

    internal static UInt128 ToNumber(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out int written))
        {
            throw new ArgumentException("Unable to read address bytes.", nameof(address));
        }

        UInt128 value = 0;
        for (int i = 0; i < written; i++)
        {
            value = (value << 8) | bytes[i];
        }

        return value;
    }

    internal static IPAddress ToAddress(AddressFamily family, UInt128 value)
    {
        int length = family == AddressFamily.InterNetwork ? 4 : 16;
        Span<byte> bytes = stackalloc byte[length];
        for (int i = length - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }

        return new IPAddress(bytes);
    }

    private static int? MaskToPrefix(IPAddress mask)
    {
        int bits = mask.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        UInt128 value = ToNumber(mask);
        int ones = 0;
        for (int i = bits - 1; i >= 0; i--)
        {
            if (((value >> i) & 1) == 1)
            {
                ones++;
            }
            else
            {
                // Remaining bits must all be zero for a contiguous mask.
                UInt128 rest = i == 0 ? UInt128.Zero : value & ((UInt128.One << i) - 1);
                return rest == 0 ? ones : null;
            }
        }

        return ones;
    }

    private static bool TryParseWildcard(string text, out IPAddressRange range)
    {
        range = default;
        var parts = text.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        uint start = 0, end = 0;
        bool seenWildcard = false;
        foreach (var part in parts)
        {
            start <<= 8;
            end <<= 8;
            if (part == "*")
            {
                seenWildcard = true;
                end |= 0xFF;
                continue;
            }

            if (seenWildcard || !byte.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out byte b))
            {
                // Wildcards must be trailing (10.*.*.*), anything else is ambiguous.
                return false;
            }

            start |= b;
            end |= b;
        }

        range = new IPAddressRange(AddressFamily.InterNetwork, start, end);
        return true;
    }
}
