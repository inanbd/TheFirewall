using System.Net;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Tests;

public class IPAddressRangeTests
{
    [Theory]
    [InlineData("1.2.3.4", "1.2.3.4")]
    [InlineData("10.0.0.0/8", "10.0.0.0/8")]
    [InlineData("10.1.2.3/8", "10.0.0.0/8")]
    [InlineData("192.168.1.10-192.168.1.20", "192.168.1.10-192.168.1.20")]
    [InlineData("192.168.1.0-192.168.1.255", "192.168.1.0/24")]
    [InlineData("172.16.*.*", "172.16.0.0/16")]
    [InlineData("10.0.0.0/255.0.0.0", "10.0.0.0/8")]
    [InlineData("::ffff:1.2.3.4", "1.2.3.4")]
    [InlineData("2001:db8::/32", "2001:db8::/32")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    [InlineData(" 8.8.8.8 ", "8.8.8.8")]
    public void Parses_and_formats(string input, string expected)
    {
        Assert.True(IPAddressRange.TryParse(input, out var range));
        Assert.Equal(expected, range.ToFirewallString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("hello")]
    [InlineData("1.2.3")]
    [InlineData("1.2.3.4/33")]
    [InlineData("1.*.3.4")]
    [InlineData("1.2.3.4-::1")]
    [InlineData("10.0.0.0/255.0.255.0")]
    public void Rejects_invalid(string input) => Assert.False(IPAddressRange.TryParse(input, out _));

    [Fact]
    public void Contains_works_for_v4_and_v6()
    {
        var range = IPAddressRange.Parse("10.0.0.0/8");
        Assert.True(range.Contains(IPAddress.Parse("10.255.1.1")));
        Assert.False(range.Contains(IPAddress.Parse("11.0.0.1")));
        Assert.True(range.Contains(IPAddress.Parse("::ffff:10.1.1.1")));
        Assert.False(range.Contains(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void Merge_combines_overlapping_and_adjacent_ranges()
    {
        var merged = IPAddressRange.Merge(
        [
            IPAddressRange.Parse("1.0.0.0/24"),
            IPAddressRange.Parse("1.0.1.0/24"),
            IPAddressRange.Parse("1.0.0.128/25"),
            IPAddressRange.Parse("5.5.5.5"),
            IPAddressRange.Parse("2001:db8::/64"),
        ]);

        Assert.Equal(["1.0.0.0/23", "5.5.5.5", "2001:db8::/64"], merged.Select(m => m.ToFirewallString()));
    }

    [Fact]
    public void Subtract_punches_holes()
    {
        var result = IPAddressRange.Subtract([IPAddressRange.Parse("10.0.0.0/24")], [IPAddressRange.Parse("10.0.0.10"), IPAddressRange.Parse("10.0.0.200-10.0.0.255")]);
        Assert.Equal(["10.0.0.0-10.0.0.9", "10.0.0.11-10.0.0.199"], result.Select(r => r.ToFirewallString()));
    }

    [Fact]
    public void Subtract_handles_exclusions_spanning_several_ranges()
    {
        var result = IPAddressRange.Subtract(
            [IPAddressRange.Parse("1.0.0.0/24"), IPAddressRange.Parse("1.0.2.0/24"), IPAddressRange.Parse("9.9.9.9")],
            [IPAddressRange.Parse("1.0.0.128-1.0.2.127")]);
        Assert.Equal(["1.0.0.0/25", "1.0.2.128/25", "9.9.9.9"], result.Select(r => r.ToFirewallString()));
    }

    [Fact]
    public void Complement_covers_everything_else()
    {
        var result = IPAddressRange.Complement([IPAddressRange.Parse("128.0.0.0/1")], includeIPv6: false);
        Assert.Equal(["0.0.0.0/1"], result.Select(r => r.ToFirewallString()));

        var full = IPAddressRange.Complement([], includeIPv4: false);
        Assert.Equal(["::/0"], full.Select(r => r.ToFirewallString()));
    }

    [Theory]
    [InlineData("1.2.3.4:5678", "1.2.3.4")]
    [InlineData("[2001:db8::1]:22", "2001:db8::1")]
    [InlineData("::ffff:192.0.2.1", "192.0.2.1")]
    [InlineData("fe80::1%12", "fe80::1")]
    [InlineData("\"8.8.4.4\"", "8.8.4.4")]
    public void TryParseAddress_tolerates_log_formats(string input, string expected)
    {
        Assert.True(IPUtility.TryParseAddress(input, out var address));
        Assert.Equal(expected, address.ToString());
    }

    [Theory]
    [InlineData("-")]
    [InlineData("WORKSTATION01")]
    [InlineData("1")]
    [InlineData("0x7f000001")]
    [InlineData("1.2.3")]
    public void TryParseAddress_rejects_non_addresses(string input) => Assert.False(IPUtility.TryParseAddress(input, out _));

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("192.168.0.5", true)]
    [InlineData("100.64.1.1", true)]
    [InlineData("::1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("172.32.0.1", false)]
    [InlineData("2001:4860::8888", false)]
    public void IsInternal(string ip, bool expected) => Assert.Equal(expected, IPUtility.IsInternal(IPAddress.Parse(ip)));
}
