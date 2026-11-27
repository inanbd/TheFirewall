using System.Net;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Firewall;
using TheFirewall.Core.Networking;

namespace TheFirewall.Core.Tests;

public class PortRuleTests
{
    // Monday 25 November 2030, UTC is used as the local time zone so the tests do not depend on the machine.
    private static readonly DateTimeOffset Monday = new(2030, 11, 25, 0, 0, 0, TimeSpan.Zero);

    private static DateTimeOffset At(int dayOffset, int hour, int minute = 0) => Monday.AddDays(dayOffset).AddHours(hour).AddMinutes(minute);

    private static PortRule Rdp(PortAccess access = PortAccess.Everyone) =>
        new() { Id = "rdp", Name = "Remote Desktop", Protocol = RuleProtocol.Tcp, Ports = "3389", Access = access };

    private static FirewallPlan Plan(FirewallSettings settings, DateTimeOffset? now = null,
        Func<IReadOnlyCollection<string>, IReadOnlyList<IPAddressRange>?>? countries = null) =>
        FirewallPlanner.Build(new FirewallPlanInput
        {
            Settings = settings,
            Now = now ?? Monday,
            TimeZone = TimeZoneInfo.Utc,
            CountryRangeLookup = countries,
        });

    private static List<FirewallRuleSpec> PortRules(FirewallPlan plan) =>
        plan.Rules.Where(r => r.Name.StartsWith("TheFirewall_Port_", StringComparison.Ordinal)).ToList();

    private static List<IPAddressRange> Ranges(FirewallRuleSpec rule) =>
        rule.RemoteAddresses.Split(',').Select(IPAddressRange.Parse).ToList();

    private static bool Covers(IEnumerable<FirewallRuleSpec> rules, string address) =>
        rules.Any(r => Ranges(r).Any(range => range.Contains(IPAddress.Parse(address))));

    [Theory]
    [InlineData(0, 7, 59, false)]   // Monday before opening
    [InlineData(0, 8, 0, true)]     // Monday at opening
    [InlineData(0, 17, 59, true)]
    [InlineData(0, 18, 0, false)]   // closing time is exclusive
    [InlineData(5, 12, 0, false)]   // Saturday
    public void Daytime_schedule(int day, int hour, int minute, bool open)
    {
        var schedule = new PortSchedule { Enabled = true, Days = WeekDays.Weekdays, From = "08:00", To = "18:00" };
        Assert.Equal(open, schedule.IsOpenAt(At(day, hour, minute).DateTime));
    }

    [Theory]
    [InlineData(4, 23, 0, true)]    // Friday night
    [InlineData(5, 3, 0, true)]     // early Saturday belongs to Friday's window
    [InlineData(5, 23, 0, false)]   // Saturday night: Saturday is not selected
    [InlineData(0, 3, 0, false)]    // early Monday belongs to Sunday's window (not selected)
    [InlineData(0, 6, 0, false)]
    public void Overnight_schedule(int day, int hour, int minute, bool open)
    {
        var schedule = new PortSchedule { Enabled = true, Days = WeekDays.Weekdays, From = "22:00", To = "06:00" };
        Assert.Equal(open, schedule.IsOpenAt(At(day, hour, minute).DateTime));
    }

    [Fact]
    public void Same_start_and_end_means_all_day()
    {
        var schedule = new PortSchedule { Enabled = true, Days = WeekDays.Weekend, From = "00:00", To = "00:00" };
        Assert.True(schedule.IsOpenAt(At(6, 23, 59).DateTime));
        Assert.False(schedule.IsOpenAt(At(0, 12).DateTime));
    }

    [Fact]
    public void Outside_the_schedule_the_port_is_closed_until_the_next_opening()
    {
        var rule = Rdp(PortAccess.Restricted);
        rule.Schedule = new PortSchedule { Enabled = true, Days = WeekDays.Weekdays, From = "08:00", To = "18:00" };

        var night = PortPolicy.Evaluate(rule, At(0, 20), TimeZoneInfo.Utc);
        Assert.Equal(PortAccess.Nobody, night.Access);
        Assert.Equal(PortStateReason.OutsideSchedule, night.Reason);
        Assert.Equal(At(1, 8), night.NextChangeUtc);

        var day = PortPolicy.Evaluate(rule, At(1, 9), TimeZoneInfo.Utc);
        Assert.Equal(PortAccess.Restricted, day.Access);
        Assert.Equal(At(1, 18), day.NextChangeUtc);

        // Friday evening: next opening is Monday morning.
        Assert.Equal(At(7, 8), PortPolicy.Evaluate(rule, At(4, 19), TimeZoneInfo.Utc).NextChangeUtc);
    }

    [Fact]
    public void Temporary_opening_wins_until_it_ends()
    {
        var rule = Rdp(PortAccess.Nobody);
        rule.OpenUntilUtc = At(0, 2);

        var state = PortPolicy.Evaluate(rule, At(0, 1), TimeZoneInfo.Utc);
        Assert.Equal(PortAccess.Everyone, state.Access);
        Assert.Equal(PortStateReason.TemporarilyOpen, state.Reason);
        Assert.Equal(At(0, 2), state.NextChangeUtc);

        Assert.Equal(PortAccess.Nobody, PortPolicy.Evaluate(rule, At(0, 2), TimeZoneInfo.Utc).Access);
        Assert.NotEqual(PortPolicy.StateKey([rule], At(0, 1), TimeZoneInfo.Utc), PortPolicy.StateKey([rule], At(0, 3), TimeZoneInfo.Utc));
    }

    [Fact]
    public void Open_port_is_one_allow_rule_per_protocol()
    {
        var settings = new FirewallSettings();
        var rule = Rdp();
        rule.Protocol = RuleProtocol.Any;
        settings.Ports.Add(rule);

        var rules = PortRules(Plan(settings));
        Assert.Equal(["TheFirewall_Port_rdp_Tcp_Open", "TheFirewall_Port_rdp_Udp_Open"], rules.Select(r => r.Name));
        Assert.All(rules, r =>
        {
            Assert.Equal(RuleAction.Allow, r.Action);
            Assert.Equal(RuleDirection.Inbound, r.Direction);
            Assert.Equal("3389", r.LocalPorts);
            Assert.Equal(string.Empty, r.RemoteAddresses);
            Assert.True(r.Enabled);
        });
    }

    [Fact]
    public void Closed_port_blocks_everyone_except_the_whitelist_and_local_network()
    {
        var settings = new FirewallSettings();
        settings.Whitelist.Add(new AddressEntry { Value = "203.0.113.10" });
        settings.Ports.Add(Rdp(PortAccess.Nobody));

        var rules = PortRules(Plan(settings));
        Assert.All(rules, r =>
        {
            Assert.Equal(RuleAction.Block, r.Action);
            Assert.Equal(RuleProtocol.Tcp, r.Protocol);
            Assert.Equal("3389", r.LocalPorts);
        });
        Assert.True(Covers(rules, "198.51.100.7"));
        Assert.True(Covers(rules, "2001:db8::1"));
        Assert.False(Covers(rules, "203.0.113.10"));   // whitelist
        Assert.False(Covers(rules, "192.168.1.20"));   // local network
        Assert.False(Covers(rules, "10.1.2.3"));
    }

    [Fact]
    public void Restricted_port_allows_listed_addresses_and_countries_and_blocks_the_rest()
    {
        var settings = new FirewallSettings();
        settings.Whitelist.Add(new AddressEntry { Value = "203.0.113.10" });
        var rule = Rdp(PortAccess.Restricted);
        rule.AllowedAddresses = "198.51.100.0/24";
        rule.AllowedCountries = ["DE"];
        settings.Ports.Add(rule);
        var germany = new List<IPAddressRange> { IPAddressRange.Parse("5.0.0.0/8") };

        var rules = PortRules(Plan(settings, countries: codes => codes.Contains("DE") ? germany : null));
        var allow = rules.Where(r => r.Action == RuleAction.Allow).ToList();
        var block = rules.Where(r => r.Action == RuleAction.Block).ToList();
        Assert.True(Covers(allow, "198.51.100.7"));
        Assert.True(Covers(allow, "5.6.7.8"));
        Assert.True(Covers(block, "8.8.8.8"));
        Assert.False(Covers(block, "198.51.100.7"));
        Assert.False(Covers(block, "5.6.7.8"));
        Assert.False(Covers(block, "203.0.113.10"));
        Assert.False(Covers(block, "192.168.1.20"));
    }

    [Fact]
    public void Restricted_port_stays_open_while_the_country_database_is_missing()
    {
        var settings = new FirewallSettings();
        var rule = Rdp(PortAccess.Restricted);
        rule.AllowedCountries = ["DE"];
        settings.Ports.Add(rule);

        var only = Assert.Single(PortRules(Plan(settings, countries: _ => null)));
        Assert.Equal(RuleAction.Allow, only.Action);
        Assert.Equal(string.Empty, only.RemoteAddresses);
    }

    [Fact]
    public void Scheduled_port_is_closed_at_night_in_the_plan()
    {
        var settings = new FirewallSettings();
        var rule = Rdp();
        rule.Schedule = new PortSchedule { Enabled = true, Days = WeekDays.All, From = "08:00", To = "18:00" };
        settings.Ports.Add(rule);

        Assert.All(PortRules(Plan(settings, At(0, 12))), r => Assert.Equal(RuleAction.Allow, r.Action));
        Assert.All(PortRules(Plan(settings, At(0, 22))), r => Assert.Equal(RuleAction.Block, r.Action));
    }

    [Fact]
    public void Invalid_ports_are_reported()
    {
        var settings = new FirewallSettings();
        settings.Ports.Add(new PortRule { Name = "", Ports = "99999" });
        settings.Ports.Add(new PortRule { Name = "Restricted", Ports = "22", Access = PortAccess.Restricted });
        settings.Ports.Add(new PortRule
        {
            Name = "Scheduled",
            Ports = "80",
            Schedule = new PortSchedule { Enabled = true, Days = WeekDays.None, From = "8am", To = "18:00" },
        });
        settings.Ports.Add(new PortRule { Name = "Fine", Ports = "443, 8000-8100", Access = PortAccess.Restricted, AllowedCountries = ["us"] });
        SettingsStore.Normalize(settings);

        var errors = SettingsStore.Validate(settings);
        Assert.Contains(errors, e => e.Contains("a name is required", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("'99999' is not a valid port", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("'Restricted': add at least one address or country", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("'Scheduled': schedule times", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("'Scheduled': choose at least one day", StringComparison.Ordinal));
        Assert.DoesNotContain(errors, e => e.Contains("'Fine'", StringComparison.Ordinal));
        Assert.Equal("443,8000-8100", settings.Ports[3].Ports);
        Assert.Equal(["US"], settings.Ports[3].AllowedCountries);
    }

    [Fact]
    public void Port_rules_survive_a_settings_round_trip()
    {
        var settings = new FirewallSettings();
        var rule = Rdp(PortAccess.Restricted);
        rule.AllowedCountries = ["DE"];
        rule.Schedule = new PortSchedule { Enabled = true, Days = WeekDays.Monday | WeekDays.Friday, From = "07:30", To = "19:00" };
        rule.OpenUntilUtc = At(0, 3);
        settings.Ports.Add(rule);

        var copy = Assert.Single(SettingsStore.Clone(settings).Ports);
        Assert.Equal(PortAccess.Restricted, copy.Access);
        Assert.Equal(WeekDays.Monday | WeekDays.Friday, copy.Schedule.Days);
        Assert.Equal("07:30", copy.Schedule.From);
        Assert.Equal(At(0, 3), copy.OpenUntilUtc);
        Assert.Equal(["DE"], copy.AllowedCountries);
    }
}

public class PortReachabilityTests
{
    private static readonly DateTimeOffset Noon = new(2030, 11, 25, 12, 0, 0, TimeSpan.Zero);

    private static Ports.ListeningPort Rdp() => new()
    {
        Protocol = "TCP",
        Port = 3389,
        Addresses = ["0.0.0.0", "::"],
        ProcessName = "svchost",
        ProcessPath = @"C:\Windows\system32\svchost.exe",
        ServiceNames = ["TermService"],
        Services = ["Remote Desktop Services"],
    };

    private static Ports.FirewallRuleInfo RdpRule(string remote = "*") => new()
    {
        Name = "Remote Desktop - User Mode (TCP-In)",
        Enabled = true,
        Allow = true,
        Protocol = 6,
        LocalPorts = "3389",
        RemoteAddresses = remote,
        ApplicationName = @"C:\Windows\System32\svchost.exe",
        ServiceName = "termservice",
        Profiles = 0x7FFFFFFF,
    };

    private static Ports.ListeningPort Evaluate(Ports.ListeningPort port, IReadOnlyList<Ports.FirewallRuleInfo> rules,
        Ports.FirewallPolicyInfo? policy = null, FirewallSettings? settings = null)
    {
        Ports.PortReachability.Evaluate(port, rules, policy ?? new Ports.FirewallPolicyInfo(), settings ?? new FirewallSettings(), Noon, TimeZoneInfo.Utc);
        return port;
    }

    [Fact]
    public void Loopback_only_ports_are_local()
    {
        var port = Rdp();
        port.Addresses = ["127.0.0.1", "::1"];
        Assert.Equal(Ports.PortExposure.LocalOnly, Evaluate(port, [RdpRule()]).Exposure);
    }

    [Fact]
    public void Windows_allow_rule_for_the_service_opens_the_port()
    {
        var port = Evaluate(Rdp(), [RdpRule()]);
        Assert.Equal(Ports.PortExposure.Open, port.Exposure);
        Assert.Contains("Remote Desktop - User Mode (TCP-In)", port.ExposureText, StringComparison.Ordinal);
    }

    [Fact]
    public void Rule_for_another_service_or_profile_does_not_count()
    {
        var otherService = RdpRule();
        otherService.ServiceName = "Spooler";
        Assert.Equal(Ports.PortExposure.Blocked, Evaluate(Rdp(), [otherService]).Exposure);

        var domainOnly = RdpRule();
        domainOnly.Profiles = 1;
        Assert.Equal(Ports.PortExposure.Blocked, Evaluate(Rdp(), [domainOnly], new Ports.FirewallPolicyInfo { CurrentProfiles = 4 }).Exposure);
    }

    [Fact]
    public void Rule_limited_to_some_addresses_and_firewall_states()
    {
        Assert.Equal(Ports.PortExposure.OpenToSome, Evaluate(Rdp(), [RdpRule("LocalSubnet")]).Exposure);
        Assert.Equal(Ports.PortExposure.Open, Evaluate(Rdp(), [], new Ports.FirewallPolicyInfo { Enabled = false }).Exposure);
        Assert.Equal(Ports.PortExposure.Open, Evaluate(Rdp(), [], new Ports.FirewallPolicyInfo { DefaultInboundBlock = false }).Exposure);
        Assert.Equal(Ports.PortExposure.Blocked, Evaluate(Rdp(), [RdpRule()], new Ports.FirewallPolicyInfo { BlockAllInbound = true }).Exposure);
    }

    [Fact]
    public void Ports_page_entry_decides_and_is_linked()
    {
        var settings = new FirewallSettings();
        settings.Ports.Add(new PortRule { Id = "rdp", Name = "Remote Desktop", Protocol = RuleProtocol.Any, Ports = "3389", Access = PortAccess.Nobody });
        var port = Evaluate(Rdp(), [RdpRule()], settings: settings);
        Assert.Equal(Ports.PortExposure.Blocked, port.Exposure);
        Assert.Equal("rdp", port.ManagedPortId);
        Assert.Contains("Closed by \"Remote Desktop\"", port.ExposureText, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("", 22, true)]
    [InlineData("*", 22, true)]
    [InlineData("80,443", 443, true)]
    [InlineData("8000-8100, 22", 8050, true)]
    [InlineData("8000-8100", 8101, false)]
    [InlineData("RPC", 135, false)]
    public void Port_lists(string list, int port, bool expected) => Assert.Equal(expected, Ports.PortReachability.PortListContains(list, port));
}

public class PackageRuleTests
{
    [Fact]
    public void Rules_for_a_store_app_do_not_open_other_programs_ports()
    {
        var port = new Ports.ListeningPort { Protocol = "TCP", Port = 45678, Addresses = ["0.0.0.0"], ProcessName = "pwsh", ProcessPath = @"C:\Program Files\PowerShell\7\pwsh.exe" };
        var packageRule = new Ports.FirewallRuleInfo
        {
            Name = "@{MicrosoftWindows.Client.OOBE_1000.26100.28.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.OOBE/resources/AppName}",
            Enabled = true,
            Allow = true,
            AppPackageId = "S-1-15-2-1234",
        };

        Ports.PortReachability.Evaluate(port, [packageRule], new Ports.FirewallPolicyInfo(), new FirewallSettings(), DateTimeOffset.UtcNow, TimeZoneInfo.Utc);
        Assert.Equal(Ports.PortExposure.Blocked, port.Exposure);
    }

    [Fact]
    public void Rule_with_an_owner_only_counts_for_programs_running_as_that_account()
    {
        var ownedBySystem = new Ports.FirewallRuleInfo
        {
            Name = "Windows Feature Experience Pack",
            Enabled = true,
            Allow = true,
            LocalUserOwner = "S-1-5-18",
            LocalUserOwnerName = @"NT AUTHORITY\SYSTEM",
        };
        Ports.ListeningPort Port(string? sid) => new() { Protocol = "TCP", Port = 45678, Addresses = ["0.0.0.0"], ProcessName = "app", UserSid = sid };

        var userProgram = Port("S-1-5-21-1-2-3-1001");
        Ports.PortReachability.Evaluate(userProgram, [ownedBySystem], new Ports.FirewallPolicyInfo(), new FirewallSettings(), DateTimeOffset.UtcNow, TimeZoneInfo.Utc);
        Assert.Equal(Ports.PortExposure.Blocked, userProgram.Exposure);

        var systemProgram = Port("S-1-5-18");
        Ports.PortReachability.Evaluate(systemProgram, [ownedBySystem], new Ports.FirewallPolicyInfo(), new FirewallSettings(), DateTimeOffset.UtcNow, TimeZoneInfo.Utc);
        Assert.Equal(Ports.PortExposure.Open, systemProgram.Exposure);
        Assert.Contains(@"running as NT AUTHORITY\SYSTEM", systemProgram.ExposureText, StringComparison.Ordinal);

        var unknownUser = Port(null);
        Ports.PortReachability.Evaluate(unknownUser, [ownedBySystem], new Ports.FirewallPolicyInfo(), new FirewallSettings(), DateTimeOffset.UtcNow, TimeZoneInfo.Utc);
        Assert.Equal(Ports.PortExposure.Blocked, unknownUser.Exposure);
    }
}
