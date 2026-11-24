using TheFirewall.Core.Configuration;

namespace TheFirewall.Core.Monitoring;

/// <summary>A failed or successful login detected in a log.</summary>
public sealed record LoginEvent
{
    public required string IPAddress { get; init; }

    public string? UserName { get; init; }

    public required string Source { get; init; }

    public string SourceId { get; init; } = string.Empty;

    public LoginEventKind Kind { get; init; } = LoginEventKind.Failed;

    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>The text that matched (trimmed), useful for troubleshooting.</summary>
    public string? LogText { get; init; }

    /// <summary>Failed attempts before ban for this source, 0 = global default.</summary>
    public int FailedAttemptsBeforeBan { get; init; }

    /// <summary>How many attempts this event represents.</summary>
    public int Count { get; init; } = 1;
}
