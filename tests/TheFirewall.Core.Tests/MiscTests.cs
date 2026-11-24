using System.Text.Json;
using TheFirewall.Core.Actions;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Engine;
using TheFirewall.Core.Feeds;
using TheFirewall.Core.Geo;
using TheFirewall.Core.Ipc;

namespace TheFirewall.Core.Tests;

public class ThreatFeedTests
{
    [Fact]
    public void Parses_common_list_formats()
    {
        const string text = """
            # Emerging threats
            1.2.3.4
            5.6.7.0/24 ; SBL12345
            {"cidr":"9.9.9.0/24","sblid":"SBL1","rir":"ripencc"}
            {"type":"metadata","timestamp":1700000000}
            10.0.0.1	7
            2001:db8::/32
            garbage line
            """;
        var ranges = ThreatFeedService.Parse(text);
        Assert.Equal(["1.2.3.4", "5.6.7.0/24", "9.9.9.0/24", "10.0.0.1", "2001:db8::/32"], ranges.Select(r => r.ToFirewallString()));
    }

    [Fact]
    public void Respects_max_entries() => Assert.Equal(2, ThreatFeedService.Parse("1.1.1.1\n2.2.2.2\n3.3.3.3", 2).Count);
}

public class GeoIpTests
{
    private const string Csv = """
        1.0.0.0,1.0.0.255,AU
        1.0.1.0,1.0.3.255,CN
        8.8.8.0,8.8.8.255,US
        2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
        2.0.0.0,2.0.0.255,ZZ
        """;

    [Fact]
    public void Lookup_and_ranges()
    {
        var db = GeoIpDatabase.Load(new StringReader(Csv), DateTimeOffset.UtcNow);
        Assert.Equal("AU", db.Lookup("1.0.0.7"));
        Assert.Equal("CN", db.Lookup("1.0.2.1"));
        Assert.Equal("US", db.Lookup("8.8.8.8"));
        Assert.Equal("JP", db.Lookup("2001:200::1"));
        Assert.Null(db.Lookup("2.0.0.1"));
        Assert.Null(db.Lookup("9.9.9.9"));
        Assert.Equal(["1.0.0.0/22"], db.GetRanges(["AU", "cn"]).Select(r => r.ToFirewallString()));
        Assert.Equal(1, db.CountRangesByCountry()["US"]);
    }

    [Fact]
    public void Country_names_are_available()
    {
        Assert.True(Countries.All.Count > 240);
        Assert.True(Countries.IsValidCode("de"));
        Assert.False(Countries.IsValidCode("QQ"));
    }
}

public class SettingsTests
{
    [Fact]
    public void Round_trips_and_normalizes()
    {
        using var dir = new TempDirectory();
        var store = new SettingsStore(dir.File("settings.json"), Log.Null);
        var defaults = store.Load();
        Assert.True(File.Exists(store.FilePath));
        Assert.True(defaults.ProtectionEnabled);
        Assert.NotEmpty(defaults.ThreatFeeds);

        defaults.BanPolicy.FailedAttemptsBeforeBan = -5;
        defaults.General.FirewallRulePrefix = "My Prefix!";
        defaults.CustomRules.Add(new CustomFirewallRule { Id = "dup", Name = "A" });
        defaults.CustomRules.Add(new CustomFirewallRule { Id = "dup", Name = "B" });
        store.Save(defaults);

        var loaded = store.Load();
        Assert.Equal(1, loaded.BanPolicy.FailedAttemptsBeforeBan);
        Assert.Equal("MyPrefix", loaded.General.FirewallRulePrefix);
        Assert.NotEqual(loaded.CustomRules[0].Id, loaded.CustomRules[1].Id);
        Assert.Equal(defaults.BanPolicy.BanDurations, loaded.BanPolicy.BanDurations);

        var json = File.ReadAllText(store.FilePath);
        Assert.Contains("\"protectionEnabled\": true", json, StringComparison.Ordinal);
        Assert.Contains("\"mode\": \"Off\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Corrupt_file_falls_back_to_defaults()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(dir.File("settings.json"), "{ not json");
        var settings = new SettingsStore(dir.File("settings.json"), Log.Null).Load();
        Assert.Equal(5, settings.BanPolicy.FailedAttemptsBeforeBan);
        Assert.Single(Directory.GetFiles(dir.Path, "settings.json.invalid-*"));
    }

    [Fact]
    public void Validation_reports_friendly_errors()
    {
        var settings = new FirewallSettings();
        settings.Whitelist.Add(new AddressEntry { Value = "not-an-ip" });
        settings.CustomRules.Add(new CustomFirewallRule { Name = "Web", Protocol = RuleProtocol.Any, LocalPorts = "80" });
        settings.CustomSources.Add(new LogSourceDefinition { Name = "Bad", Kind = LogSourceKind.TextFile, PathMasks = "C:/x/*.log", Regex = "(unclosed" });
        var errors = SettingsStore.Validate(settings);
        Assert.Contains(errors, e => e.Contains("not-an-ip", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("ports can only be used with TCP or UDP", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("invalid regular expression", StringComparison.Ordinal));
    }

    [Fact]
    public void Source_overrides_apply_to_builtins()
    {
        var settings = new FirewallSettings();
        settings.SourceOverrides["mssql"] = new SourceOverride { Enabled = false, FailedAttemptsBeforeBan = 9 };
        var mssql = SourceCatalog.GetEffective(settings).Single(s => s.Id == "mssql");
        Assert.False(mssql.Enabled);
        Assert.Equal(9, mssql.FailedAttemptsBeforeBan);
        Assert.True(mssql.IsBuiltIn);
        Assert.True(BuiltInSources.Find("mssql")!.Enabled);
    }
}

public class MiscUnitTests
{
    [Theory]
    [InlineData(0, "permanently")]
    [InlineData(30, "30 minutes")]
    [InlineData(60, "1 hour")]
    [InlineData(1440, "1 day")]
    [InlineData(10080, "1 week")]
    [InlineData(4320, "3 days")]
    public void Durations_are_human_readable(int minutes, string expected) =>
        Assert.Equal(expected, TimeFormat.Duration(TimeSpan.FromMinutes(minutes)));

    [Theory]
    [InlineData("\"C:\\Program Files\\x\\run.exe\" --ip {ip}", "C:\\Program Files\\x\\run.exe", "--ip {ip}")]
    [InlineData("C:\\x\\run.exe|###IPADDRESS### -q", "C:\\x\\run.exe", "###IPADDRESS### -q")]
    [InlineData("notify.exe {ip}", "notify.exe", "{ip}")]
    public void Command_lines_are_parsed(string line, string file, string args)
    {
        Assert.True(ProcessLauncher.TryParse(line, out var f, out var a));
        Assert.Equal(file, f);
        Assert.Equal(args, a);
    }

    [Fact]
    public void Placeholders_strip_quotes()
    {
        var result = ProcessLauncher.ReplacePlaceholders("--user \"{user}\" --ip ###IPADDRESS###",
            new Dictionary<string, string?> { ["user"] = "x\" & calc", ["ip"] = "1.2.3.4" });
        Assert.Equal("--user \"x & calc\" --ip 1.2.3.4", result);
    }

    [Fact]
    public void Levenshtein() => Assert.Equal(1, PolicyContext.Levenshtein("alice", "alicr", 3));

    [Fact]
    public void Ipc_json_uses_string_enums()
    {
        var json = JsonSerializer.Serialize(new CustomFirewallRule { Action = RuleAction.Allow, Profiles = RuleProfiles.Domain | RuleProfiles.Private }, IpcJson.Options);
        Assert.Contains("\"action\":\"Allow\"", json, StringComparison.Ordinal);
        Assert.Contains("\"profiles\":\"Domain, Private\"", json, StringComparison.Ordinal);
        var back = JsonSerializer.Deserialize<CustomFirewallRule>(json, IpcJson.Options)!;
        Assert.Equal(RuleProfiles.Domain | RuleProfiles.Private, back.Profiles);
    }
}

public class CountryValidationTests
{
    [Fact]
    public void Allow_only_without_countries_is_rejected()
    {
        var settings = new FirewallSettings();
        settings.CountryBlocking.Mode = CountryBlockingMode.AllowOnlySelected;
        Assert.Contains(SettingsStore.Validate(settings), e => e.Contains("at least one country", StringComparison.Ordinal));

        settings.CountryBlocking.Countries = ["DE", "XX"];
        var errors = SettingsStore.Validate(settings);
        Assert.DoesNotContain(errors, e => e.Contains("at least one country", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("'XX'", StringComparison.Ordinal));
    }
}
