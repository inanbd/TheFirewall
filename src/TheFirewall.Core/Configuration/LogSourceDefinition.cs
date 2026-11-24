using System.Text.Json.Serialization;

namespace TheFirewall.Core.Configuration;

[JsonConverter(typeof(JsonStringEnumConverter<LogSourceKind>))]
public enum LogSourceKind
{
    /// <summary>A Windows event log channel, e.g. "Security" or "OpenSSH/Operational".</summary>
    EventLog,

    /// <summary>Plain text log files matched by a path mask.</summary>
    TextFile,
}

[JsonConverter(typeof(JsonStringEnumConverter<LoginEventKind>))]
public enum LoginEventKind
{
    Failed,
    Successful,
}

/// <summary>An XPath selection inside an event's XML plus an optional regular expression the selected value must match.</summary>
public sealed class EventXPathExpression
{
    public string XPath { get; set; } = string.Empty;

    /// <summary>
    /// Regular expression applied to each selected node. Named groups: ipaddress, ipaddress_exact, username,
    /// source, source_NAME, log, timestamp, timestamp_utc. Empty means the node only has to exist.
    /// </summary>
    public string Regex { get; set; } = string.Empty;

    /// <summary>When true the event still matches if this expression does not (used to pick up optional data such as a user name).</summary>
    public bool Optional { get; set; }
}

/// <summary>
/// Describes where failed (or successful) logins are detected: a Windows event log with XPath/regex
/// expressions, or text files with a regular expression.
/// </summary>
public sealed class LogSourceDefinition
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..10];

    /// <summary>Friendly name shown in the UI.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Short source tag stored with every event, e.g. "RDP", "SSH", "MSSQL".</summary>
    public string Source { get; set; } = string.Empty;

    public string Category { get; set; } = "Custom";

    public string Description { get; set; } = string.Empty;

    public LogSourceKind Kind { get; set; } = LogSourceKind.EventLog;

    public LoginEventKind EventKind { get; set; } = LoginEventKind.Failed;

    public bool Enabled { get; set; } = true;

    /// <summary>Failed attempts before ban for this source, 0 to use the global setting.</summary>
    public int FailedAttemptsBeforeBan { get; set; }

    // ---- Event log ----

    /// <summary>Event log channel, e.g. "Security", "Application", "OpenSSH/Operational".</summary>
    public string LogName { get; set; } = string.Empty;

    /// <summary>Structured XML/XPath query for the event subscription. Empty means every event of the log.</summary>
    public string Query { get; set; } = string.Empty;

    public List<EventXPathExpression> Expressions { get; set; } = [];

    // ---- Text files ----

    /// <summary>
    /// One path mask per line. Supports * and ** globbing plus {year}, {month}, {day} placeholders
    /// (UTC) and {year-local}, {month-local}, {day-local}.
    /// </summary>
    public string PathMasks { get; set; } = string.Empty;

    /// <summary>Regular expression applied to new log text. Same named groups as event expressions.</summary>
    public string Regex { get; set; } = string.Empty;

    /// <summary>Optional exact format of the timestamp group, e.g. "MM/dd/yy HH:mm:ss".</summary>
    public string TimestampFormat { get; set; } = string.Empty;

    public int PollIntervalSeconds { get; set; } = 10;

    [JsonIgnore]
    public bool IsBuiltIn { get; internal set; }

    public LogSourceDefinition Clone()
    {
        var clone = (LogSourceDefinition)MemberwiseClone();
        clone.Expressions = Expressions.Select(e => new EventXPathExpression { XPath = e.XPath, Regex = e.Regex, Optional = e.Optional }).ToList();
        return clone;
    }
}
