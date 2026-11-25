using TheFirewall.Core.Configuration;
using TheFirewall.Core.Monitoring;

namespace TheFirewall.Core.Tests;

public class EventXmlMatcherTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 20, 10, 30, 0, TimeSpan.Zero);

    internal const string Rdp4625 = """
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-11-20T10:15:30.1234567Z'/><EventRecordID>12345</EventRecordID><Correlation/><Execution ProcessID='648' ThreadID='1234'/><Channel>Security</Channel><Computer>SERVER01</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>administrator</Data><Data Name='TargetDomainName'></Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>-</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>45.141.84.10</Data><Data Name='IpPort'>0</Data></EventData></Event>
        """;

    [Fact]
    public void Rdp_failed_logon_extracts_ip_and_user()
    {
        var evt = EventXmlMatcher.Match(BuiltInSources.Find("rdp-logon")!, Rdp4625, Now);
        Assert.NotNull(evt);
        Assert.Equal("45.141.84.10", evt.IPAddress);
        Assert.Equal("administrator", evt.UserName);
        Assert.Equal("RDP", evt.Source);
        Assert.Equal(LoginEventKind.Failed, evt.Kind);
        Assert.Equal(new DateTimeOffset(2026, 11, 20, 10, 15, 30, TimeSpan.Zero), evt.Timestamp, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Failed_logon_is_never_a_successful_sign_in()
    {
        Assert.Null(EventXmlMatcher.Match(BuiltInSources.Find("rdp-success")!, Rdp4625, Now));
    }

    [Fact]
    public void Remote_desktop_sign_in_is_detected()
    {
        var xml = Rdp4625.Replace("<EventID>4625</EventID>", "<EventID>4624</EventID>").Replace("<Data Name='LogonType'>3</Data>", "<Data Name='LogonType'>10</Data>");
        var evt = EventXmlMatcher.Match(BuiltInSources.Find("rdp-success")!, xml, Now);
        Assert.NotNull(evt);
        Assert.Equal(LoginEventKind.Successful, evt.Kind);
        Assert.Equal("administrator", evt.UserName);

        // A network logon (type 3, e.g. a file share) is not a Remote Desktop sign-in.
        Assert.Null(EventXmlMatcher.Match(BuiltInSources.Find("rdp-success")!, xml.Replace("<Data Name='LogonType'>10</Data>", "<Data Name='LogonType'>3</Data>"), Now));
    }

    [Fact]
    public void Rdp_failed_logon_without_ip_is_ignored()
    {
        var xml = Rdp4625.Replace("<Data Name='IpAddress'>45.141.84.10</Data>", "<Data Name='IpAddress'>-</Data>");
        Assert.Null(EventXmlMatcher.Match(BuiltInSources.Find("rdp-logon")!, xml, Now));
    }

    [Fact]
    public void Iis_process_overrides_source()
    {
        var xml = Rdp4625.Replace("<Data Name='ProcessName'>-</Data>", @"<Data Name='ProcessName'>C:\Windows\System32\inetsrv\w3wp.exe</Data>");
        var evt = EventXmlMatcher.Match(BuiltInSources.Find("rdp-logon")!, xml, Now);
        Assert.Equal("IIS", evt?.Source);
    }

    [Fact]
    public void Sql_server_failed_login()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQL$SQLEXPRESS'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2026-11-20T10:00:00.000Z'/><EventRecordID>1</EventRecordID><Channel>Application</Channel><Computer>SQL01</Computer><Security/></System><EventData><Data>sa</Data><Data> Reason: Password did not match that for the login provided.</Data><Data> [CLIENT: 203.0.113.50]</Data><Binary>184800000E000000</Binary></EventData></Event>
            """;
        var evt = EventXmlMatcher.Match(BuiltInSources.Find("mssql")!, xml, Now);
        Assert.NotNull(evt);
        Assert.Equal("203.0.113.50", evt.IPAddress);
        Assert.Equal("sa", evt.UserName);
        Assert.Equal("MSSQL", evt.Source);
    }

    [Fact]
    public void Sql_server_database_unavailable_is_ignored()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Channel>Application</Channel></System><EventData><Data>appuser</Data><Data> Reason: Failed to open the explicitly specified database 'db'.</Data><Data> [CLIENT: 203.0.113.50]</Data></EventData></Event>
            """;
        Assert.Null(EventXmlMatcher.Match(BuiltInSources.Find("mssql")!, xml, Now));
    }

    [Fact]
    public void OpenSsh_failed_password()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='OpenSSH'/><EventID>4</EventID><Channel>OpenSSH/Operational</Channel></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>Failed password for invalid user admin from 198.51.100.23 port 51234 ssh2</Data></EventData></Event>
            """;
        var evt = EventXmlMatcher.Match(BuiltInSources.Find("ssh-openssh")!, xml, Now);
        Assert.NotNull(evt);
        Assert.Equal("198.51.100.23", evt.IPAddress);
        Assert.Equal("admin", evt.UserName);
        Assert.Equal("SSH", evt.Source);
    }

    [Fact]
    public void OpenSsh_success_is_a_successful_login()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='OpenSSH'/><EventID>4</EventID><Channel>OpenSSH/Operational</Channel></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>Accepted publickey for bob from 198.51.100.7 port 60000 ssh2: ED25519 SHA256:abc</Data></EventData></Event>
            """;
        var evt = EventXmlMatcher.Match(BuiltInSources.Find("ssh-success")!, xml, Now);
        Assert.NotNull(evt);
        Assert.Equal(LoginEventKind.Successful, evt.Kind);
        Assert.Equal("bob", evt.UserName);
    }

    [Fact]
    public void MySql_access_denied()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MySQL'/><EventID>100</EventID><Channel>Application</Channel></System><EventData><Data>Access denied for user 'root'@'203.0.113.9' (using password: YES)</Data></EventData></Event>
            """;
        var evt = EventXmlMatcher.Match(BuiltInSources.Find("mysql")!, xml, Now);
        Assert.Equal("203.0.113.9", evt?.IPAddress);
        Assert.Equal("root", evt?.UserName);
    }

    [Fact]
    public void Custom_application_event()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MyApp'/><EventID>1</EventID><Channel>Application</Channel></System><EventData><Data>2026-11-20T10:00:00Z, thefirewall failed login, ip address: 203.0.113.77, source: Portal, user: alice</Data></EventData></Event>
            """;
        var evt = EventXmlMatcher.Match(BuiltInSources.Find("custom-eventlog")!, xml, Now);
        Assert.Equal("203.0.113.77", evt?.IPAddress);
        Assert.Equal("Portal", evt?.Source);
        Assert.Equal("alice", evt?.UserName);
    }

    [Fact]
    public void Rras_denied()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='RemoteAccess'/><EventID>20271</EventID><Channel>System</Channel></System><EventData><Data>{guid}</Data><Data>vpnuser</Data><Data>203.0.113.200</Data><Data>The remote connection was denied because the user name and password combination you provided is not recognized.</Data></EventData></Event>
            """;
        var evt = EventXmlMatcher.Match(BuiltInSources.Find("rras")!, xml, Now);
        Assert.Equal("203.0.113.200", evt?.IPAddress);
        Assert.Equal("vpnuser", evt?.UserName);
    }

    [Fact]
    public void Invalid_xml_returns_null() => Assert.Null(EventXmlMatcher.Match(BuiltInSources.Find("rdp-logon")!, "<not xml", Now));

    [Fact]
    public void All_builtin_sources_have_valid_patterns()
    {
        foreach (var source in BuiltInSources.All)
        {
            if (source.Kind == LogSourceKind.TextFile)
            {
                Assert.Null(LoginRegex.Validate(source.Regex));
                Assert.NotNull(LoginRegex.Get(source.Regex));
            }
            else
            {
                Assert.NotEmpty(source.Expressions);
                foreach (var expression in source.Expressions)
                {
                    Assert.Null(LoginRegex.Validate(expression.Regex));
                    System.Xml.XPath.XPathExpression.Compile(expression.XPath);
                }
            }
        }

        Assert.Equal(BuiltInSources.All.Count, BuiltInSources.All.Select(s => s.Id).Distinct().Count());
    }
}
