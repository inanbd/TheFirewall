using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.Services;

/// <summary>Everything the UI needs from the service. Implemented over the named pipe, or with fake data in demo mode.</summary>
public interface IFirewallClient
{
    bool IsConnected { get; }

    /// <summary>Whether the service accepts changes from this app (it runs elevated).</summary>
    bool CanMakeChanges { get; }

    string? ServiceVersion { get; }

    ServiceStatusDto? LastStatus { get; }

    bool IsDemo { get; }

    /// <summary>Raised on the UI thread when the connection is established or lost.</summary>
    event EventHandler? ConnectionChanged;

    /// <summary>Raised on the UI thread for every new activity entry.</summary>
    event EventHandler<ActivityEntry>? ActivityReceived;

    /// <summary>Raised on the UI thread when the service reports a new status.</summary>
    event EventHandler<ServiceStatusDto>? StatusReceived;

    void Start();

    Task StopAsync();

    Task<ServiceStatusDto> GetStatusAsync();

    Task<DashboardStats> GetStatsAsync();

    Task<List<ActivityEntry>> QueryActivityAsync(ActivityQuery query);

    Task<List<IPRecord>> GetBansAsync();

    Task<List<IPRecord>> GetWatchedAsync(int limit = 1000);

    Task BanAsync(BanRequest request);

    Task<int> UnbanAsync(UnbanRequest request);

    Task<int> ClearBansAsync();

    Task<int> ImportBansAsync(ImportBansRequest request);

    Task<LookupResult> LookupAsync(string ip);

    Task<FirewallSettings> GetSettingsAsync();

    Task<SaveSettingsResponse> SaveSettingsAsync(FirewallSettings settings);

    Task<ServiceStatusDto> SetProtectionAsync(bool enabled);

    Task<List<SourceInfoDto>> GetSourcesAsync();

    Task<SourceTestResult> TestSourceAsync(SourceTestRequest request);

    Task<List<CountryDto>> GetCountriesAsync();

    Task<ServiceStatusDto> UpdateGeoAsync();

    Task<List<FeedInfoDto>> GetFeedsAsync();

    Task<List<FeedInfoDto>> RefreshFeedsAsync();
}
