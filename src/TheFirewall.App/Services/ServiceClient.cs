using System.IO;
using System.Text.Json;
using System.Windows.Threading;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.Services;

/// <summary>Talks to the Windows service over its named pipe and reconnects automatically.</summary>
public sealed class ServiceClient(Dispatcher dispatcher) : IFirewallClient
{
    private readonly CancellationTokenSource stop = new();
    private IpcClient? client;
    private Task? loop;
    private bool connected;

    public bool IsConnected => connected && client?.IsConnected == true;

    public bool CanMakeChanges { get; private set; }

    public string? ServiceVersion { get; private set; }

    public ServiceStatusDto? LastStatus { get; private set; }

    public bool IsDemo => false;

    public event EventHandler? ConnectionChanged;

    public event EventHandler<ActivityEntry>? ActivityReceived;

    public event EventHandler<ServiceStatusDto>? StatusReceived;

    public event EventHandler<ActivityEntry>? ActivityUpdated;

    public event EventHandler<IReadOnlyList<long>>? ActivityRemoved;

    public void Start() => loop ??= Task.Run(() => ConnectionLoopAsync(stop.Token));

    public async Task StopAsync()
    {
        await stop.CancelAsync();
        if (client is not null)
        {
            await client.DisposeAsync();
        }

        if (loop is not null)
        {
            try
            {
                await loop.WaitAsync(TimeSpan.FromSeconds(3));
            }
            catch (Exception)
            {
            }
        }
    }

    private async Task ConnectionLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            if (client is { IsConnected: true })
            {
                await Task.Delay(1000, token).ConfigureAwait(false);
                continue;
            }

            var candidate = new IpcClient();
            try
            {
                await candidate.ConnectAsync(TimeSpan.FromSeconds(2), token).ConfigureAwait(false);
                candidate.EventReceived += OnEvent;
                candidate.Disconnected += OnDisconnected;
                await candidate.RequestAsync(IpcCommands.Subscribe, cancellationToken: token).ConfigureAwait(false);
                var hello = await candidate.RequestAsync<HelloResponse>(IpcCommands.Hello, cancellationToken: token).ConfigureAwait(false);
                var status = await candidate.RequestAsync<ServiceStatusDto>(IpcCommands.Status, cancellationToken: token).ConfigureAwait(false);
                var previous = client;
                client = candidate;
                if (previous is not null)
                {
                    previous.Disconnected -= OnDisconnected;
                    previous.EventReceived -= OnEvent;
                    _ = previous.DisposeAsync().AsTask();
                }

                CanMakeChanges = hello?.IsAdministrator == true;
                ServiceVersion = hello?.ServiceVersion;
                LastStatus = status;
                SetConnected(true);
                if (status is not null)
                {
                    await dispatcher.InvokeAsync(() => StatusReceived?.Invoke(this, status));
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                await candidate.DisposeAsync().ConfigureAwait(false);
                break;
            }
            catch (Exception)
            {
                candidate.Disconnected -= OnDisconnected;
                await candidate.DisposeAsync().ConfigureAwait(false);
                SetConnected(false);
                try
                {
                    await Task.Delay(2000, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private void OnDisconnected()
    {
        SetConnected(false);
    }

    private void SetConnected(bool value)
    {
        if (connected == value)
        {
            return;
        }

        connected = value;
        dispatcher.InvokeAsync(() => ConnectionChanged?.Invoke(this, EventArgs.Empty));
    }

    private void OnEvent(string type, JsonElement payload)
    {
        try
        {
            if (type == IpcCommands.EventActivity)
            {
                var entry = payload.Deserialize<ActivityEntry>(IpcJson.Options);
                if (entry is not null)
                {
                    dispatcher.InvokeAsync(() => ActivityReceived?.Invoke(this, entry));
                }
            }
            else if (type == IpcCommands.EventActivityUpdated)
            {
                var entry = payload.Deserialize<ActivityEntry>(IpcJson.Options);
                if (entry is not null)
                {
                    dispatcher.InvokeAsync(() => ActivityUpdated?.Invoke(this, entry));
                }
            }
            else if (type == IpcCommands.EventActivityRemoved)
            {
                var removed = payload.Deserialize<ActivityRemovedEvent>(IpcJson.Options);
                if (removed is { Ids.Count: > 0 })
                {
                    dispatcher.InvokeAsync(() => ActivityRemoved?.Invoke(this, removed.Ids));
                }
            }
            else if (type == IpcCommands.EventStatus)
            {
                var status = payload.Deserialize<ServiceStatusDto>(IpcJson.Options);
                if (status is not null)
                {
                    LastStatus = status;
                    dispatcher.InvokeAsync(() => StatusReceived?.Invoke(this, status));
                }
            }
        }
        catch (JsonException)
        {
        }
    }

    private IpcClient Client => client is { IsConnected: true } c ? c : throw new IOException("TheFirewall service is not running or not reachable.");

    private Task<T> Request<T>(string command, object? payload = null) => RequestCore<T>(command, payload);

    private async Task<T> RequestCore<T>(string command, object? payload)
    {
        var result = await Client.RequestAsync<T>(command, payload).ConfigureAwait(true);
        if (result is null)
        {
            throw new IOException($"The service returned no data for '{command}'.");
        }

        return result;
    }

    public Task<ServiceStatusDto> GetStatusAsync() => Request<ServiceStatusDto>(IpcCommands.Status);

    public Task<DashboardStats> GetStatsAsync() => Request<DashboardStats>(IpcCommands.Stats);

    public Task<List<ActivityEntry>> QueryActivityAsync(ActivityQuery query) => Request<List<ActivityEntry>>(IpcCommands.Activity, query);

    public Task<List<IPRecord>> GetBansAsync() => Request<List<IPRecord>>(IpcCommands.Bans);

    public Task<List<IPRecord>> GetWatchedAsync(int limit = 1000) => Request<List<IPRecord>>(IpcCommands.Watched, new WatchedListRequest { Limit = limit });

    public Task BanAsync(BanRequest request) => Client.RequestAsync(IpcCommands.Ban, request);

    public Task<int> UnbanAsync(UnbanRequest request) => Request<int>(IpcCommands.Unban, request);

    public Task<int> ClearBansAsync() => Request<int>(IpcCommands.ClearBans);

    public Task<int> ImportBansAsync(ImportBansRequest request) => Request<int>(IpcCommands.ImportBans, request);

    public Task<LookupResult> LookupAsync(string ip) => Request<LookupResult>(IpcCommands.Lookup, new LookupRequest { IPAddress = ip });

    public Task<FirewallSettings> GetSettingsAsync() => Request<FirewallSettings>(IpcCommands.GetSettings);

    public Task<SaveSettingsResponse> SaveSettingsAsync(FirewallSettings settings) => Request<SaveSettingsResponse>(IpcCommands.SaveSettings, settings);

    public Task<ServiceStatusDto> SetProtectionAsync(bool enabled) => Request<ServiceStatusDto>(IpcCommands.SetProtection, new ProtectionRequest { Enabled = enabled });

    public Task<List<SourceInfoDto>> GetSourcesAsync() => Request<List<SourceInfoDto>>(IpcCommands.Sources);

    public Task<SourceTestResult> TestSourceAsync(SourceTestRequest request) => Request<SourceTestResult>(IpcCommands.TestSource, request);

    public Task<List<CountryDto>> GetCountriesAsync() => Request<List<CountryDto>>(IpcCommands.Countries);

    public Task<ServiceStatusDto> UpdateGeoAsync() => Request<ServiceStatusDto>(IpcCommands.UpdateGeo);

    public Task<List<FeedInfoDto>> GetFeedsAsync() => Request<List<FeedInfoDto>>(IpcCommands.Feeds);

    public Task<List<FeedInfoDto>> RefreshFeedsAsync() => Request<List<FeedInfoDto>>(IpcCommands.RefreshFeeds);
}
