using TheFirewall.Core.Configuration;
using TheFirewall.Core.Monitoring;

namespace TheFirewall.Core.Tests;

public class LogFileMonitorTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 20, 10, 30, 0, TimeSpan.Zero);

    private static List<LoginEvent> Parse(string sourceId, string text)
    {
        var def = BuiltInSources.Find(sourceId)!;
        return LogFileMonitor.ParseText(def, LoginRegex.Get(def.Regex)!, text.Replace("\r\n", "\n") + "\n", Now).ToList();
    }

    [Fact]
    public void Custom_log_line()
    {
        var events = Parse("custom-logfile", "2026-11-20T10:29:00Z, thefirewall failed login, ip address: 203.0.113.5, source: Portal, user: bob");
        var evt = Assert.Single(events);
        Assert.Equal("203.0.113.5", evt.IPAddress);
        Assert.Equal("bob", evt.UserName);
        Assert.Equal("Portal", evt.Source);
        Assert.Equal(new DateTimeOffset(2026, 11, 20, 10, 29, 0, TimeSpan.Zero), evt.Timestamp);
    }

    [Fact]
    public void Ipban_custom_format_is_supported()
    {
        var events = Parse("custom-logfile", "2026-11-20 10:29:00, ipban failed login, ip address: 203.0.113.6, source: Legacy, user: x");
        Assert.Equal("203.0.113.6", Assert.Single(events).IPAddress);
    }

    [Fact]
    public void Iis_ftp_failed_login()
    {
        const string log = """
            #Software: Microsoft Internet Information Services 10.0
            #Fields: date time c-ip cs-username s-ip s-port cs-method cs-uri-stem sc-status sc-win32-status sc-substatus x-session x-fullpath
            2026-11-20 10:20:01 203.0.113.44 - 10.0.0.5 21 USER admin 331 0 0 abc -
            2026-11-20 10:20:01 203.0.113.44 admin 10.0.0.5 21 PASS *** 530 1326 41 abc -
            2026-11-20 10:20:05 198.51.100.1 bob 10.0.0.5 21 PASS *** 230 0 0 def /
            """;
        var evt = Assert.Single(Parse("iis-ftp", log));
        Assert.Equal("203.0.113.44", evt.IPAddress);
        Assert.Equal("admin", evt.UserName);
        Assert.Equal("FTP", evt.Source);
    }

    [Fact]
    public void HMailServer_failed_auth()
    {
        const string log = "\"SMTPD\"\t3172\t13\t\"2026-11-20 10:20:57.427\"\t\"185.220.101.4\"\t\"SENT: 535 Authentication failed. Restricted access.\"\n" +
                           "\"IMAPD\"\t5420\t188\t\"2026-11-20 10:21:29.180\"\t\"203.0.113.8\"\t\"SENT: A01 NO Invalid user name or password.\"\n" +
                           "\"SMTPD\"\t3172\t14\t\"2026-11-20 10:22:00.000\"\t\"203.0.113.9\"\t\"SENT: 250 Hello.\"";
        var events = Parse("hmailserver", log);
        Assert.Equal(["185.220.101.4", "203.0.113.8"], events.Select(e => e.IPAddress));
    }

    [Fact]
    public void MailEnable_smtp_auth_failure()
    {
        const string log = "11/20/26 10:20:19\tSMTP-IN\t6468E5679CDC4F53AFB8064FA9FA29E6.MAI\t2816\t21.74.49.152\tAUTH\tdmNjMjAxOQ==\t535 Invalid Username or Password\t34\t14\tuser.name@domain.com\t";
        var evt = Assert.Single(Parse("mailenable", log));
        Assert.Equal("21.74.49.152", evt.IPAddress);
    }

    [Fact]
    public void RdWeb_failed_login()
    {
        const string log = "2026-11-20 10:20:20 1.2.3.4 POST /RDWeb/Pages/en-US/login.aspx - 443 - 203.0.113.12 Mozilla/5.0 - 200 0 0 391\n" +
                           "2026-11-20 10:21:20 1.2.3.4 POST /RDWeb/Pages/en-US/login.aspx - 443 bob 203.0.113.13 Mozilla/5.0 - 302 0 0 31";
        var evt = Assert.Single(Parse("rdweb", log));
        Assert.Equal("203.0.113.12", evt.IPAddress);
    }

    [Fact]
    public void Exchange_protocol_log()
    {
        const string log = "2026-11-20T10:09:27.508Z,00000000002A64E8,2,5.5.5.5:993,109.75.46.81:40016,user.name@domain.com,23,31,30,authenticate,plain,\"R=\"\"2 NO AUTHENTICATE failed.\"\";Msg=\"\"AuthFailed:LogonDenied,User: user.name@domain.com\"\";ErrMsg=AuthFailed:LogonDenied\"";
        var evt = Assert.Single(Parse("exchange-protocol", log));
        Assert.Equal("109.75.46.81", evt.IPAddress);
    }

    [Fact]
    public void Tails_files_and_skips_existing_history()
    {
        using var dir = new TempDirectory();
        var logA = dir.File("app-a.log");
        File.WriteAllText(logA, "2026-11-20T10:00:00Z, thefirewall failed login, ip address: 203.0.113.1, source: A, user: old\n");

        var def = new LogSourceDefinition
        {
            Id = "test",
            Name = "Test",
            Source = "Test",
            Kind = LogSourceKind.TextFile,
            PathMasks = dir.Path + "/*.log",
            Regex = BuiltInSources.Find("custom-logfile")!.Regex,
            PollIntervalSeconds = 1,
        };

        var received = new List<LoginEvent>();
        var time = new ManualTimeProvider(Now);
        using var monitor = new LogFileMonitor(received.Add, null, Log.Null, time);
        monitor.Configure([def]);

        monitor.PollAll(force: true);
        Assert.Empty(received); // history is not replayed

        File.AppendAllText(logA, "2026-11-20T10:30:00Z, thefirewall failed login, ip address: 203.0.113.2, source: A, user: new\r\npartial line without newline");
        monitor.PollAll(force: true);
        Assert.Equal("203.0.113.2", Assert.Single(received).IPAddress);

        // A file that appears later (log rotation) is read from the start.
        File.WriteAllText(dir.File("app-b.log"), "2026-11-20T10:30:00Z, thefirewall failed login, ip address: 203.0.113.3, source: B, user: x\n");
        monitor.PollAll(force: true);
        Assert.Equal(["203.0.113.2", "203.0.113.3"], received.Select(r => r.IPAddress));

        // Completing the partial line is picked up.
        File.AppendAllText(logA, "\n2026-11-20T10:30:00Z, thefirewall failed login, ip address: 203.0.113.4, source: A, user: y\n");
        monitor.PollAll(force: true);
        Assert.Equal("203.0.113.4", received[^1].IPAddress);

        // Truncation restarts from the beginning.
        File.WriteAllText(logA, "2026-11-20T10:30:00Z, thefirewall failed login, ip address: 203.0.113.5, source: A, user: z\n");
        monitor.PollAll(force: true);
        Assert.Equal("203.0.113.5", received[^1].IPAddress);

        var status = Assert.Single(monitor.GetStatuses());
        Assert.Equal(SourceState.Active, status.State);
        Assert.Equal(2, status.FilesWatched);
    }

    [Fact]
    public void Missing_folder_reports_not_detected()
    {
        var def = new LogSourceDefinition { Id = "x", Kind = LogSourceKind.TextFile, PathMasks = "/does/not/exist/**/*.log", Regex = "(?<ipaddress>.+)" };
        using var monitor = new LogFileMonitor(_ => { }, null, Log.Null);
        monitor.Configure([def]);
        monitor.PollAll(force: true);
        Assert.Equal(SourceState.NotDetected, Assert.Single(monitor.GetStatuses()).State);
    }

    [Fact]
    public void Placeholders_are_replaced()
    {
        Assert.Equal("log-2026-11-20.txt", LogFileMonitor.ReplacePlaceholders("log-{year}-{month}-{day}.txt", Now));
    }
}
