using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Geo;

/// <summary>
/// In-memory country lookup built from the DB-IP "IP to Country Lite" CSV (CC BY 4.0, https://db-ip.com).
/// Lines look like: <c>1.0.0.0,1.0.0.255,AU</c>.
/// </summary>
public sealed class GeoIpDatabase
{
    private readonly uint[] v4Start;
    private readonly uint[] v4End;
    private readonly ushort[] v4Country;
    private readonly UInt128[] v6Start;
    private readonly UInt128[] v6End;
    private readonly ushort[] v6Country;
    private readonly string[] codes;

    private GeoIpDatabase(uint[] v4Start, uint[] v4End, ushort[] v4Country, UInt128[] v6Start, UInt128[] v6End, ushort[] v6Country, string[] codes, DateTimeOffset buildDate)
    {
        this.v4Start = v4Start;
        this.v4End = v4End;
        this.v4Country = v4Country;
        this.v6Start = v6Start;
        this.v6End = v6End;
        this.v6Country = v6Country;
        this.codes = codes;
        BuildDate = buildDate;
    }

    public DateTimeOffset BuildDate { get; }

    public int RangeCount => v4Start.Length + v6Start.Length;

    public static GeoIpDatabase Load(string path, DateTimeOffset? buildDate = null)
    {
        using var file = File.OpenRead(path);
        Stream stream = path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? new GZipStream(file, CompressionMode.Decompress) : file;
        using (stream)
        using (var reader = new StreamReader(stream))
        {
            return Load(reader, buildDate ?? File.GetLastWriteTimeUtc(path));
        }
    }

    public static GeoIpDatabase Load(TextReader reader, DateTimeOffset buildDate)
    {
        var codeIndex = new Dictionary<string, ushort>(StringComparer.OrdinalIgnoreCase);
        var codeList = new List<string>();
        var v4 = new List<(uint Start, uint End, ushort Code)>(400_000);
        var v6 = new List<(UInt128 Start, UInt128 End, ushort Code)>(400_000);

        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var parts = line.Split(',');
            if (parts.Length < 3)
            {
                continue;
            }

            var code = parts[2].Trim().Trim('"');
            if (code.Length != 2 || code.Equals("ZZ", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!IPAddress.TryParse(parts[0].Trim().Trim('"'), out var start) || !IPAddress.TryParse(parts[1].Trim().Trim('"'), out var end) ||
                start.AddressFamily != end.AddressFamily)
            {
                continue;
            }

            if (!codeIndex.TryGetValue(code, out var index))
            {
                index = (ushort)codeList.Count;
                codeIndex[code] = index;
                codeList.Add(code.ToUpperInvariant());
            }

            var s = IPAddressRange.ToNumber(start);
            var e = IPAddressRange.ToNumber(end);
            if (start.AddressFamily == AddressFamily.InterNetwork)
            {
                v4.Add(((uint)s, (uint)e, index));
            }
            else
            {
                v6.Add((s, e, index));
            }
        }

        if (v4.Count == 0)
        {
            throw new InvalidDataException("The GeoIP file contains no IPv4 ranges.");
        }

        v4.Sort((a, b) => a.Start.CompareTo(b.Start));
        v6.Sort((a, b) => a.Start.CompareTo(b.Start));
        return new GeoIpDatabase(
            v4.Select(x => x.Start).ToArray(), v4.Select(x => x.End).ToArray(), v4.Select(x => x.Code).ToArray(),
            v6.Select(x => x.Start).ToArray(), v6.Select(x => x.End).ToArray(), v6.Select(x => x.Code).ToArray(),
            [.. codeList], buildDate);
    }

    /// <summary>Returns the ISO country code of an address, or null when unknown.</summary>
    public string? Lookup(string? ip) => IPUtility.TryParseAddress(ip, out var address) ? Lookup(address) : null;

    public string? Lookup(IPAddress address)
    {
        address = IPUtility.Normalize(address);
        var value = IPAddressRange.ToNumber(address);
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            int i = FindIndex(v4Start, (uint)value);
            return i >= 0 && v4End[i] >= (uint)value ? codes[v4Country[i]] : null;
        }

        int j = FindIndex(v6Start, value);
        return j >= 0 && v6End[j] >= value ? codes[v6Country[j]] : null;
    }

    /// <summary>All (merged) address ranges that belong to the given countries.</summary>
    public List<IPAddressRange> GetRanges(IEnumerable<string> countryCodes)
    {
        var wanted = new HashSet<ushort>();
        foreach (var c in countryCodes)
        {
            int idx = Array.FindIndex(codes, x => x.Equals(c, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                wanted.Add((ushort)idx);
            }
        }

        var ranges = new List<IPAddressRange>();
        for (int i = 0; i < v4Start.Length; i++)
        {
            if (wanted.Contains(v4Country[i]))
            {
                ranges.Add(new IPAddressRange(AddressFamily.InterNetwork, v4Start[i], v4End[i]));
            }
        }

        for (int i = 0; i < v6Start.Length; i++)
        {
            if (wanted.Contains(v6Country[i]))
            {
                ranges.Add(new IPAddressRange(AddressFamily.InterNetworkV6, v6Start[i], v6End[i]));
            }
        }

        return IPAddressRange.Merge(ranges);
    }

    /// <summary>Number of ranges per country code.</summary>
    public Dictionary<string, int> CountRangesByCountry()
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in v4Country.Concat(v6Country))
        {
            var code = codes[c];
            counts[code] = counts.TryGetValue(code, out var n) ? n + 1 : 1;
        }

        return counts;
    }

    private static int FindIndex<T>(T[] starts, T value) where T : IComparable<T>
    {
        int lo = 0, hi = starts.Length - 1, result = -1;
        while (lo <= hi)
        {
            int mid = lo + ((hi - lo) / 2);
            if (starts[mid].CompareTo(value) <= 0)
            {
                result = mid;
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return result;
    }
}
