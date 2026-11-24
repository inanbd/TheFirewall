using System.Text.Json;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Ipc;

namespace TheFirewall.Core.Service;

/// <summary>Maps pipe commands to <see cref="FirewallCoordinator"/> calls.</summary>
public sealed class CoordinatorRequestHandler(FirewallCoordinator coordinator) : IIpcRequestHandler
{
    public async Task<object?> HandleAsync(string command, JsonElement? payload, IpcClientInfo client, CancellationToken cancellationToken)
    {
        switch (command)
        {
            case IpcCommands.Hello:
                return new HelloResponse
                {
                    ServiceVersion = coordinator.Version,
                    MachineName = Environment.MachineName,
                    IsAdministrator = client.IsAdministrator,
                    UserName = client.UserName,
                };

            case IpcCommands.Status:
                return coordinator.GetStatus();

            case IpcCommands.Stats:
                return coordinator.GetStats();

            case IpcCommands.Activity:
                return coordinator.QueryActivity(Read<ActivityQuery>(payload) ?? new ActivityQuery());

            case IpcCommands.Bans:
                return coordinator.GetBans();

            case IpcCommands.Watched:
                return coordinator.GetWatched((Read<WatchedListRequest>(payload) ?? new WatchedListRequest()).Limit);

            case IpcCommands.Lookup:
                return coordinator.Lookup(Require<LookupRequest>(payload).IPAddress);

            case IpcCommands.GetSettings:
                return coordinator.Settings;

            case IpcCommands.Sources:
                return coordinator.GetSources();

            case IpcCommands.TestSource:
                return FirewallCoordinator.TestSource(Require<SourceTestRequest>(payload));

            case IpcCommands.Countries:
                return coordinator.GetCountries();

            case IpcCommands.Feeds:
                return coordinator.GetFeeds();

            // ---- Changes (the server only lets elevated clients get here)
            case IpcCommands.Ban:
                coordinator.Ban(Require<BanRequest>(payload));
                return null;

            case IpcCommands.Unban:
                return await coordinator.UnbanAsync(Require<UnbanRequest>(payload), cancellationToken).ConfigureAwait(false);

            case IpcCommands.ClearBans:
                return coordinator.ClearBans();

            case IpcCommands.ImportBans:
                return coordinator.ImportBans(Require<ImportBansRequest>(payload));

            case IpcCommands.SaveSettings:
                return await coordinator.SaveSettingsAsync(Require<FirewallSettings>(payload), cancellationToken).ConfigureAwait(false);

            case IpcCommands.SetProtection:
                await coordinator.SetProtectionAsync(Require<ProtectionRequest>(payload).Enabled, cancellationToken).ConfigureAwait(false);
                return coordinator.GetStatus();

            case IpcCommands.UpdateGeo:
                if (!await coordinator.UpdateGeoAsync(force: true, cancellationToken).ConfigureAwait(false))
                {
                    throw new IpcException(coordinator.GetStatus().GeoDatabaseError ?? "The country database could not be updated.");
                }

                return coordinator.GetStatus();

            case IpcCommands.RefreshFeeds:
                await coordinator.RefreshFeedsAsync(force: true, cancellationToken).ConfigureAwait(false);
                return coordinator.GetFeeds();

            case IpcCommands.SyncFirewall:
                await coordinator.SyncFirewallAsync(cancellationToken).ConfigureAwait(false);
                return coordinator.GetStatus();

            default:
                throw new IpcException($"Unknown command '{command}'.", IpcErrorCodes.NotFound);
        }
    }

    private static T? Read<T>(JsonElement? payload) where T : class =>
        payload is { ValueKind: not JsonValueKind.Null and not JsonValueKind.Undefined } p ? p.Deserialize<T>(IpcJson.Options) : null;

    private static T Require<T>(JsonElement? payload) where T : class =>
        Read<T>(payload) ?? throw new IpcException("The request is missing its data.");
}
