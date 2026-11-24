namespace TheFirewall.Core.Configuration;

/// <summary>
/// Built-in login sources. Covers everything IPBan detects on Windows plus a few extras (IIS FTP, hMailServer).
/// Several expressions are adapted from IPBan (MIT License, Copyright (c) 2012-present Digital Ruby, LLC).
/// </summary>
public static class BuiltInSources
{
    public const string RemoteAccess = "Remote access";
    public const string Databases = "Databases";
    public const string Mail = "Mail servers";
    public const string Web = "Web & FTP";
    public const string Other = "Other";

    // Event log keyword "Audit Failure" (0x10000000000000).
    private const string AuditFailure = "band(Keywords,4503599627370496)";

    private const string IpDataXPath = "//Data[@Name='IpAddress' or @Name='SourceAddress' or @Name='CallingStationID' or @Name='ClientIPAddress' or @Name='RemoteAddress']";

    private const string SshFailedRegex = """
        (?<log>failed\s+password)\s+for\s+(?:invalid\s+user\s+)?(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh|
        (?<log>did\s+not\s+receive\s+identification\s+string)\s+from\s+(?<ipaddress>[^\s]+)|
        (?<log>connection\s+(?:closed|reset))\s+by\s+(?:(?:(?:invalid|authenticating)\s+user\s+)?(?<username>[^\s]+)\s+)?(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|
        (?<log>disconnected\s+from)\s+(?:invalid\s+user\s+)?(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|
        (?<log>disconnected\s+from)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|
        (?<log>disconnected\s+from\s+authenticating\s+user)\s+(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|
        (?<log>invalid\s+user)\s+(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+
        """;

    private const string CustomFailedRegex = """
        (?<timestamp>\d\d\d\d-\d\d-\d\d[\sT]\d\d:\d\d:\d\d(?:\.\d+)?Z?)?(?:,\s)?
        (?<log>(?:thefirewall|ipban)\sfailed\slogin),\sip\saddress:\s(?<ipaddress>[^,\n]+),\ssource:\s(?<source>[^,\n]+)?,\suser:\s(?<username>[^\s,]+)?
        """;

    private const string CustomSuccessRegex = """
        (?<timestamp>\d\d\d\d-\d\d-\d\d[\sT]\d\d:\d\d:\d\d(?:\.\d+)?Z?)?(?:,\s)?
        (?<log>(?:thefirewall|ipban)\ssuccess\slogin),\sip\saddress:\s(?<ipaddress>[^,\n]+),\ssource:\s(?<source>[^,\n]+)?,\suser:\s(?<username>[^\s,]+)?
        """;

    private static readonly Lazy<IReadOnlyList<LogSourceDefinition>> Definitions = new(Create);

    public static IReadOnlyList<LogSourceDefinition> All => Definitions.Value;

    public static LogSourceDefinition? Find(string id) => All.FirstOrDefault(s => string.Equals(s.Id, id, StringComparison.OrdinalIgnoreCase));

    private static IReadOnlyList<LogSourceDefinition> Create()
    {
        var list = new List<LogSourceDefinition>
        {
            // ------------------------------------------------------------------ Remote access
            EventLog("rdp-logon", "Windows logon / RDP", "RDP", RemoteAccess,
                "Failed Windows logons (event 4625) including Remote Desktop, SMB and IIS basic auth, Kerberos pre-authentication failures (4768) and NPS/RADIUS denials (6273).",
                "Security", $"*[System[(EventID=4625 or EventID=4768 or EventID=6273) and {AuditFailure}]]",
                X("//EventID", @"^(?<log>4625|4768|6273)$"),
                X(IpDataXPath, @"(?<ipaddress>.+)"),
                X("//Data[@Name='TargetUserName' or @Name='SubjectUserName']", @"^(?!-$)(?<username>.+)$", optional: true),
                X("//Data[@Name='ProcessName']", @"(?<source_IIS>\\inetsrv\\w3wp\.exe)$", optional: true)),

            EventLog("rdp-ipsec", "Windows logon (IPsec / NTLM disabled)", "RDP", RemoteAccess,
                "IPsec main mode negotiation failures (event 4653), seen on servers with NTLM disabled.",
                "Security", $"*[System[(EventID=4653) and {AuditFailure}]]",
                X("//EventID", @"^(?<log>4653)$"),
                X("//Data[@Name='FailureReason']", "."),
                X("//Data[@Name='RemoteAddress']", @"(?<ipaddress>.+)")),

            EventLog("rdp-rdpcorets", "Remote Desktop protocol errors", "RDP", RemoteAccess,
                "Remote Desktop connections that fail NLA or use an invalid protocol (RdpCoreTS event 140), a typical sign of RDP scanners.",
                "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "*[System[(Opcode=14)]]",
                X("//Opcode", @"^(?<log>14)$"),
                X("//Data[@Name='ClientIP' or @Name='IPString']", @"(?<ipaddress>.+)")),

            EventLog("ssh-openssh", "OpenSSH server", "SSH", RemoteAccess,
                "Failed password, invalid user and pre-auth disconnects reported by the Windows OpenSSH server.",
                "OpenSSH/Operational", string.Empty,
                X("//Data[@Name='payload']", SshFailedRegex)),

            EventLog("ssh-application", "OpenSSH server (Application log)", "SSH", RemoteAccess,
                "Older OpenSSH builds that write 'invalid user' messages to the Application log.",
                "Application", "*[System[(EventID=0)]]",
                X("//EventID", "^0$"),
                X("//Data", @"^sshd:\spid\s[0-9]+:\s(?<log>invalid\suser)\s(?<username>[^\s]+)\sfrom\s(?<ipaddress>[^\s]+)\sport\s[0-9]+")),

            EventLog("vnc", "VNC server", "VNC", RemoteAccess,
                "Authentication failures from RealVNC / TightVNC style servers (event 258).",
                "Application", "*[System[(EventID=258)]]",
                X("//EventID", "^258$"),
                X("//Data", @"(?<log>Authentication\sfailed)\sfrom\s(?<ipaddress>.+)")),

            EventLog("rras", "VPN / RRAS", "RRAS", RemoteAccess,
                "Routing and Remote Access (VPN) connections that were denied (event 20271).",
                "System", "*[System[(EventID=20271)]]",
                X("//EventID", "^20271$"),
                X("(//Data)[2]", @"(?<username>.*)", optional: true),
                X("(//Data)[3]", @"(?<ipaddress>.+)"),
                X("(//Data)[4]", @"(?<log>denied|connection\swas\sprevented|Die\sRemoteverbindung\swurde\sverweigert)")),

            TextFile("rdweb", "RD Web Access", "RDWeb", RemoteAccess,
                "Failed sign-ins to the Remote Desktop Web Access page (IIS logs).",
                "C:/inetpub/logs/LogFiles/W3SVC*/*.log",
                """(?<timestamp_utc>\d\d\d\d\-\d\d\-\d\d\s\d\d\:\d\d\:\d\d)\s[^\s]+\sPOST\s\/RDWeb\/Pages\/[^\/]+\/login\.aspx\s[^\s]+\s[0-9]+\s-\s(?<ipaddress>[^\s]+).*\s(?<log>200)\s[^\n]+"""),

            // ------------------------------------------------------------------ Databases
            EventLog("mssql", "Microsoft SQL Server", "MSSQL", Databases,
                "Failed SQL Server logins (event 18456). Failures caused by an unavailable database are ignored.",
                "Application", "*[System[(EventID=18456)]]",
                X("//Provider[contains(@Name,'MSSQL')]", string.Empty),
                X("//EventID", @"^(?<log>18456)$"),
                X("(//Data)[1]", @"^(?<username>.+)$", optional: true),
                X("(//Data)[2]", @"^(?:(?!Reason:\sFailed\sto\sopen\sthe(?:\sexplicitly\sspecified)?\sdatabase)(?:.))+$"),
                X("(//Data)[3]", @"\[CLIENTE?\s?:\s?(?<ipaddress>[^\]]+)\]")),

            EventLog("mysql", "MySQL / MariaDB", "MySQL", Databases,
                "'Access denied for user' errors written to the Application log by MySQL or MariaDB.",
                "Application", "*[System[Provider[@Name='MySQL' or @Name='MariaDB']]]",
                X("//Provider[@Name='MySQL' or @Name='MariaDB']", string.Empty),
                X("//Data", @"(?<log>Access\sdenied\sfor\suser)\s'?(?<username>[^']+)'@'(?<ipaddress>[^']+)'")),

            EventLog("postgresql", "PostgreSQL", "PostgreSQL", Databases,
                "PostgreSQL authentication failures logged to the Application log (requires %h in log_line_prefix).",
                "Application", "*[System[Provider[@Name='PostgreSQL']]]",
                X("//Provider[@Name='PostgreSQL']", string.Empty),
                X("//Data", @"(?<log>authentication\sfailed|no\spg_hba\.conf\sentry)[^\n]*?host=""?(?<ipaddress>[^\s"",]+)|host=""?(?<ipaddress>[^\s"",]+)[^\n]*?(?<log>authentication\sfailed|no\spg_hba\.conf\sentry)")),

            EventLog("phpmyadmin", "phpMyAdmin", "phpMyAdmin", Databases,
                "Denied phpMyAdmin logins written to the Application log.",
                "Application", string.Empty,
                X("//Data", "phpMyAdmin"),
                X("//Data", @"(?<log>user\sdenied):\s+(?<username>[^\s]+)\s+\(mysql-denied\)\s+from\s+(?<ipaddress>.+)")),

            // ------------------------------------------------------------------ Mail
            EventLog("exchange-transport", "Microsoft Exchange (event log)", "MSExchange", Mail,
                "LogonDenied events from the Exchange transport service.",
                "System", "*[System[Provider[@Name='MSExchangeTransport']]]",
                X("//Provider[@Name='MSExchangeTransport']", string.Empty),
                X("//Data", @"(?<log>LogonDenied)"),
                X("//Data", @"(?<ipaddress_exact>.+)")),

            TextFile("exchange-protocol", "Microsoft Exchange (protocol logs)", "MSExchange", Mail,
                "Failed SMTP/IMAP/POP authentication in Exchange front-end protocol logs.",
                "C:/Program Files/Microsoft/Exchange Server/*/TransportRoles/Logs/FrontEnd/ProtocolLog/**/*.log",
                """
                ^(?<timestamp>[0-9TZ\-:\.]+),(?:.*?\\(?:.*?),)?(?:[^,\n]*,){3}(?<ipaddress>[^,\n]+).*?
                (?:(?:504\s5\.7\.4\s(?<log>Unrecognized\sauthentication\stype))|(?:(?<log>LogonDenied)\n?.*?(?:User\:|User\sName\:)\s(?<username>[^\n,"]+)))
                """),

            TextFile("smartermail", "SmarterMail", "SmarterMail", Mail,
                "Failed logins and brute-force detections in SmarterMail logs.",
                """
                C:/Program Files/Smarter Tools/Smarter Mail/**/*.log
                C:/Program Files (x86)/Smarter Tools/Smarter Mail/**/*.log
                C:/SmarterMail/logs/**/*.log
                C:/Smarter Mail/logs/**/*.log
                """,
                """
                \[(?<ipaddress>[^\]\n]+)\](?:\[[^\]\n]*\]\s+).*?
                (?<log>
                login\sfailed|
                IP\sis\sblacklisted|
                Authentication\sfailed|
                EHLO\sSMTP\sblocking\srule|
                rsp:\s554\sSecurity\sfailure|
                too\smany\sauthentication\sfailures|
                Mail\srejected\sdue\sto\sSMTP\sSpam\sBlocking|
                IP\sblocked\sby\sbrute\sforce\sabuse\sdetection\srule|
                The\sdomain\sgiven\sin\sthe\sEHLO\scommand\sviolates\san\sEHLO\sSMTP
                )
                """),

            TextFile("mailenable", "MailEnable", "MailEnable", Mail,
                "Invalid SMTP AUTH and IMAP logins in MailEnable activity logs.",
                """
                C:/Program Files (x86)/Mail Enable/Logging/SMTP/SMTP-Activity-*.log
                C:/Program Files/Mail Enable/Logging/SMTP/SMTP-Activity-*.log
                C:/Program Files (x86)/Mail Enable/Logging/IMAP/*.log
                C:/Program Files/Mail Enable/Logging/IMAP/*.log
                """,
                """
                ^(?<timestamp>[0-9\/:\s]+)SMTP\-IN\s+[^\s]+\s+[^\s]+\s(?<ipaddress>[^\s]+)\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+(?<log>Invalid\sUsername\sor\sPassword)\s+[^\s]+\s+[^\s]+\s+(?<username>[^\n]+)$|
                ^(?<timestamp>[0-9\/:\s]+)IMAP\-IN\s+[^\s]+\s+(?<ipaddress>[^\s]+)\s+LOGIN\s+LOGIN\s+"(?<username>[^"]+)"\s+"[^"]+"\s+[^\s]+\s+NO\s+LOGIN\s+Failed\s+[^\s]+\s+(?<log>Invalid\s+username\s+or\s+password)[^\n]*$|
                ^(?<timestamp>[0-9\/:\s]+)\sSMTP\-IN\s[^\s]+\s[^\s]+\s(?<ipaddress>[^\s]+)\s[^\s]+\s[^\s]+\sTO\:(?<username>[^\s]+)\s[^\s]+\sthis\smail\sserver\srequires\sauthentication\swhen\sattempting\sto\ssend\sto\sa\snon-local\se-mail\saddress[^\n]+$|
                ^(?<timestamp>[0-9\/:\s]+)\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+(?<ipaddress>[^\s]+)\s+.*\s(?<log>denied\saccess)\s+[^\n]+$
                """,
                timestampFormat: "MM/dd/yy HH:mm:ss"),

            TextFile("hmailserver", "hMailServer", "hMailServer", Mail,
                "Failed SMTP, IMAP and POP3 authentication in hMailServer logs.",
                """
                C:/Program Files (x86)/hMailServer/Logs/hmailserver_*.log
                C:/Program Files/hMailServer/Logs/hmailserver_*.log
                """,
                """^"(?:SMTPD|IMAPD|POP3D)"\s+[0-9]+\s+[0-9]+\s+"(?<timestamp>[^"]+)"\s+"(?<ipaddress>[^"]+)"\s+"SENT:\s+[^"\n]*?(?<log>Authentication\sfailed|Invalid\suser\sname\sor\spassword)"""),

            // ------------------------------------------------------------------ Web & FTP
            TextFile("iis-ftp", "IIS FTP server", "FTP", Web,
                "Failed FTP logins (status 530) in Microsoft FTP Service W3C logs.",
                "C:/inetpub/logs/LogFiles/FTPSVC*/*.log",
                """^(?<timestamp_utc>\d{4}-\d\d-\d\d\s\d\d:\d\d:\d\d)\s(?<ipaddress>[^\s]+)\s(?<username>[^\s]+)\s[^\s]+\s[0-9]+\sPASS\s[^\s]+\s(?<log>530)\s"""),

            TextFile("apache", "Apache / Tomcat (400/403 responses)", "Apache", Web,
                "Bans clients that trigger HTTP 400/403 responses or probe for php/cgi exploits. Aggressive: review before enabling.",
                """
                C:/Program Files/Tomcat/logs/**/*access_log*.txt
                C:/Apache24/logs/access*.log
                """,
                """^(?<ipaddress>[^\s]+)\s.*?\[(?<timestamp>.*?)\].*?(?:\s(?<log>40[03])\s(-|[0-9]+)|((php|md5sum|cgi-bin|joomla).*?\s(?<log>40[03]\s[0-9]+|\s400\s-)))[^\n]*""",
                timestampFormat: "dd/MMM/yyyy:HH:mm:ss zzz",
                enabled: false),

            // ------------------------------------------------------------------ Other
            EventLog("svn", "VisualSVN Server", "SVN", Other,
                "Wrong passwords reported by VisualSVN Server (event 1004).",
                "VisualSVNServer", "*[System[(EventID=1004)]]",
                X("//EventID", "^1004$"),
                X("(//Data)[1]", @"user\s(?<username>.*?):\s\(.*\)\s.*?(?<log>falsch|wrong|incorrect|bad)"),
                X("(//Data)[2]", @"(?<ipaddress_exact>.+)")),

            EventLog("custom-eventlog", "Custom application events", "Custom", Other,
                "Your own applications can report failures by writing 'thefirewall failed login, ip address: 1.2.3.4, source: MyApp, user: bob' to the Application log. IPBan-formatted messages also work.",
                "Application", string.Empty,
                X("//Data", CustomFailedRegex)),

            TextFile("custom-logfile", "Custom log files", "Custom", Other,
                "Write lines like '2026-01-01T01:01:01Z, thefirewall failed login, ip address: 1.2.3.4, source: MyApp, user: bob' to %ProgramData%\\TheFirewall\\CustomLogs\\*.log (C:\\IPBanCustomLogs is also read).",
                """
                %ProgramData%/TheFirewall/CustomLogs/**/*.log
                C:/IPBanCustomLogs/**/*.log
                """,
                CustomFailedRegex),

            // ------------------------------------------------------------------ Successful logins (activity feed + optional counter reset)
            Success(EventLog("rdp-success", "Remote Desktop sign-ins", "RDP", RemoteAccess,
                "Successful Remote Desktop sign-ins (event 4624, logon type 10). Shown in the activity feed.",
                "Security", "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']]",
                X("//Data[@Name='IpAddress']", @"(?<ipaddress>.+)"),
                X("//Data[@Name='TargetUserName']", @"^(?<username>.+)$", optional: true))),

            Success(EventLog("ssh-success", "OpenSSH sign-ins", "SSH", RemoteAccess,
                "Successful OpenSSH password or key sign-ins.",
                "OpenSSH/Operational", string.Empty,
                X("//Data[@Name='payload']", @"Accepted\s+(?:password|publickey)\s+for\s+(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh"))),

            Success(EventLog("vnc-success", "VNC sign-ins", "VNC", RemoteAccess,
                "Successful VNC authentication (event 257).",
                "Application", "*[System[(EventID=257)]]",
                X("//EventID", "^257$"),
                X("//Data", @"Authentication\spassed\sby\s(?<ipaddress>.+)"))),

            Success(EventLog("mssql-success", "SQL Server sign-ins", "MSSQL", Databases,
                "Successful SQL Server logins (event 18454). Can be very noisy on busy servers.",
                "Application", "*[System[(EventID=18454)]]",
                X("//Provider[contains(@Name,'MSSQL')]", string.Empty),
                X("(//Data)[1]", @"^(?<username>.+)$", optional: true),
                X("(//Data)[2]", @"\[CLIENTE?\s?:\s?(?<ipaddress>[^\]]+)\]")), enabled: false),

            Success(EventLog("custom-eventlog-success", "Custom application sign-ins", "Custom", Other,
                "'thefirewall success login, ip address: ..., source: ..., user: ...' messages in the Application log.",
                "Application", string.Empty,
                X("//Data", CustomSuccessRegex))),
        };

        foreach (var source in list)
        {
            source.IsBuiltIn = true;
        }

        return list;
    }

    private static EventXPathExpression X(string xpath, string regex, bool optional = false) =>
        new() { XPath = xpath, Regex = regex, Optional = optional };

    private static LogSourceDefinition EventLog(string id, string name, string source, string category, string description,
        string logName, string query, params EventXPathExpression[] expressions) => new()
        {
            Id = id,
            Name = name,
            Source = source,
            Category = category,
            Description = description,
            Kind = LogSourceKind.EventLog,
            LogName = logName,
            Query = query,
            Expressions = [.. expressions],
        };

    private static LogSourceDefinition TextFile(string id, string name, string source, string category, string description,
        string pathMasks, string regex, string timestampFormat = "", bool enabled = true) => new()
        {
            Id = id,
            Name = name,
            Source = source,
            Category = category,
            Description = description,
            Kind = LogSourceKind.TextFile,
            PathMasks = pathMasks,
            Regex = regex,
            TimestampFormat = timestampFormat,
            Enabled = enabled,
        };

    private static LogSourceDefinition Success(LogSourceDefinition definition, bool enabled = true)
    {
        definition.EventKind = LoginEventKind.Successful;
        definition.Enabled = enabled;
        return definition;
    }
}
