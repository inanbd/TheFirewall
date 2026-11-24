using System.Text.Json.Serialization;

namespace TheFirewall.Core.Monitoring;

[JsonConverter(typeof(JsonStringEnumConverter<SourceState>))]
public enum SourceState
{
    /// <summary>Turned off by the user.</summary>
    Disabled,

    /// <summary>Running and watching for events.</summary>
    Active,

    /// <summary>Enabled, but the product is not installed here (event log or folder does not exist).</summary>
    NotDetected,

    /// <summary>Something went wrong; see the message.</summary>
    Error,
}

/// <summary>Runtime status of a login source.</summary>
public sealed class SourceStatus
{
    public string SourceId { get; set; } = string.Empty;

    public SourceState State { get; set; }

    public string? Message { get; set; }

    public DateTimeOffset? LastEventUtc { get; set; }

    public long EventsDetected { get; set; }

    public int FilesWatched { get; set; }
}

/// <summary>Detects login events and reports them through a callback.</summary>
public interface ILoginMonitor : IDisposable
{
    /// <summary>Starts (or restarts) monitoring the given sources. Sources of other kinds are ignored.</summary>
    void Configure(IReadOnlyList<Configuration.LogSourceDefinition> sources);

    /// <summary>Current status of each configured source this monitor handles.</summary>
    IReadOnlyList<SourceStatus> GetStatuses();
}

/// <summary>Persists read positions of text log files so a restart neither misses nor re-reads lines.</summary>
public interface IFilePositionStore
{
    IReadOnlyDictionary<string, long> LoadFilePositions();

    void SaveFilePositions(IReadOnlyDictionary<string, long> positions);
}
