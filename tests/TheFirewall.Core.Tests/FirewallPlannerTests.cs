using TheFirewall.Core.Configuration;
using TheFirewall.Core.Firewall;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Tests;

public class FirewallPlannerTests
{
    private static IEnumerable<string> Addresses(int count, int offset = 0) =>
        Enumerable.Range(offset, count).Select(i => $"203.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}");

    [Fact]
    public void Bans_are_split_into_rules_of_1000()
    {
        var plan = FirewallPlanner.Build(new FirewallPlanInput { Settings = new FirewallSettings(), BannedAddresses = [.. Addresses(2500)] });
        var banRules = plan.Rules.Where(r => r.Name.StartsWith("TheFirewall_Ban_", StringComparison.Ordinal)).ToList();
        Assert.Equal(3, banRules.Count);
        Assert.Equal(2500, banRules.Sum(r => r.RemoteAddresses.Split(',').Length));
        Assert.All(banRules, r => Assert.Equal(RuleAction.Block, r.Action));
        Assert.Equal("TheFirewall_Ban_0000", banRules[0].Name);
    }

    [Fact]
    public void Ban_chunks_stay_stable_when_one_address_changes()
    {
        var settings = new FirewallSettings();
        var first = FirewallPlanner.Build(new FirewallPlanInput { Settings = settings, BannedAddresses = [.. Addresses(2000)] });

        // Unban one address from the first rule and ban a new one.
        var next = Addresses(2000).Skip(1).Append("198.51.100.1").ToList();
        var second = FirewallPlanner.Build(new FirewallPlanInput { Settings = settings, BannedAddresses = next, PreviousBanChunks = first.BanChunks });

        var changed = second.Rules.Where(r => first.Rules.First(f => f.Name == r.Name).ComputeHash() != r.ComputeHash()).ToList();
        Assert.Equal("TheFirewall_Ban_0000", Assert.Single(changed).Name);
    }

    [Fact]
    public void Whitelist_is_removed_from_blacklist_and_paused_protection_disables_rules()
    {
        var settings = new FirewallSettings { ProtectionEnabled = false };
        settings.Blacklist.Add(new AddressEntry { Value = "198.51.100.0/24" });
        settings.Whitelist.Add(new AddressEntry { Value = "198.51.100.128/25" });
        var plan = FirewallPlanner.Build(new FirewallPlanInput { Settings = settings });
        var rule = Assert.Single(plan.Rules);
        Assert.Equal("TheFirewall_Blacklist_0000", rule.Name);
        Assert.Equal("198.51.100.0/25", rule.RemoteAddresses);
        Assert.False(rule.Enabled);
    }

    [Fact]
    public void Allow_only_countries_blocks_the_complement_but_never_local_networks()
    {
        var settings = new FirewallSettings();
        settings.CountryBlocking.Mode = CountryBlockingMode.AllowOnlySelected;
        settings.CountryBlocking.Countries = ["XX"];
        settings.CountryBlocking.Ports = "3389, 22";
        var allowed = new List<IPAddressRange> { IPAddressRange.Parse("1.0.0.0/8") };

        var plan = FirewallPlanner.Build(new FirewallPlanInput { Settings = settings, CountryRanges = allowed });
        var tcp = plan.Rules.Where(r => r.Name.StartsWith("TheFirewall_CountryTcp_", StringComparison.Ordinal)).ToList();
        var udp = plan.Rules.Where(r => r.Name.StartsWith("TheFirewall_CountryUdp_", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(tcp);
        Assert.Equal(tcp.Count, udp.Count);
        Assert.All(tcp, r => Assert.Equal("3389,22", r.LocalPorts));

        var blocked = tcp.SelectMany(r => r.RemoteAddresses.Split(',')).Select(IPAddressRange.Parse).ToList();
        Assert.DoesNotContain(blocked, b => b.Contains(System.Net.IPAddress.Parse("1.2.3.4")));
        Assert.DoesNotContain(blocked, b => b.Contains(System.Net.IPAddress.Parse("192.168.1.1")));
        Assert.DoesNotContain(blocked, b => b.Contains(System.Net.IPAddress.Parse("10.0.0.1")));
        Assert.Contains(blocked, b => b.Contains(System.Net.IPAddress.Parse("8.8.8.8")));
        Assert.Contains(blocked, b => b.Contains(System.Net.IPAddress.Parse("2001:4860::8888")));
    }

    [Fact]
    public void Custom_rules_are_translated()
    {
        var settings = new FirewallSettings();
        settings.CustomRules.Add(new CustomFirewallRule
        {
            Id = "abc",
            Name = "Allow RDP from office",
            Action = RuleAction.Allow,
            Protocol = RuleProtocol.Tcp,
            LocalPorts = "3389",
            RemoteAddresses = "203.0.113.0/24, LocalSubnet, 198.51.100.7",
        });
        var spec = Assert.Single(FirewallPlanner.Build(new FirewallPlanInput { Settings = settings }).Rules);
        Assert.Equal("TheFirewall_Rule_abc", spec.Name);
        Assert.Equal(RuleAction.Allow, spec.Action);
        Assert.Equal("3389", spec.LocalPorts);
        Assert.Equal("198.51.100.7,203.0.113.0/24,LocalSubnet", spec.RemoteAddresses);
    }

    [Theory]
    [InlineData("80, 443 ,8000-8100", true, "80,443,8000-8100")]
    [InlineData("", true, "")]
    [InlineData("any", true, "")]
    [InlineData("0", false, "")]
    [InlineData("70000", false, "")]
    [InlineData("90-80", false, "")]
    [InlineData("http", false, "")]
    public void Port_validation(string input, bool valid, string expected)
    {
        Assert.Equal(valid, FirewallPlanner.TryNormalizePorts(input, out var normalized, out _));
        if (valid)
        {
            Assert.Equal(expected, normalized);
        }
    }

    [Fact]
    public void Synchronizer_only_writes_changed_rules()
    {
        using var dir = new TempDirectory();
        using var db = new Data.FirewallDatabase(dir.File("fw.db"));
        var backend = new InMemoryFirewallBackend();
        backend.SetRule(new FirewallRuleSpec { Name = "TheFirewall_Stale" });
        backend.SetRule(new FirewallRuleSpec { Name = "SomeoneElse" });
        var sync = new FirewallSynchronizer(backend, db, Log.Null);
        var settings = new FirewallSettings();

        var plan = FirewallPlanner.Build(new FirewallPlanInput { Settings = settings, BannedAddresses = ["203.0.113.1"] });
        var result = sync.Apply(plan, "TheFirewall_");
        Assert.Equal(1, result.Updated);
        Assert.Equal(1, result.Deleted);
        Assert.Contains("SomeoneElse", backend.Rules.Keys);
        Assert.DoesNotContain("TheFirewall_Stale", backend.Rules.Keys);

        var again = sync.Apply(plan, "TheFirewall_");
        Assert.Equal(0, again.Updated);
        Assert.Equal(1, again.Unchanged);

        Assert.Equal(1, sync.RemoveAll("TheFirewall_"));
        Assert.Equal(["SomeoneElse"], backend.Rules.Keys);
    }
}
