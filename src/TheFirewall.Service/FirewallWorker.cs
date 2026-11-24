using System.Net.Http.Headers;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TheFirewall.Core;
using TheFirewall.Core.Ipc;
using TheFirewall.Core.Service;
using TheFirewall.Service.Windows;

namespace TheFirewall.Service;

/// <summary>Hosts the coordinator and the named pipe server for the lifetime of the Windows service.</summary>
[SupportedOSPlatform("windows")]
internal sealed class FirewallWorker(ILoggerFactory loggerFactory, IHostApplicationLifetime lifetime) : BackgroundService
{
    private readonly ILogger logger = loggerFactory.CreateLogger<FirewallWorker>();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        FirewallCoordinator? coordinator = null;
        IpcServer? server = null;
        using var http = CreateHttpClient();
        try
        {
            var paths = FirewallPaths.Default;
            var backend = new WindowsFirewallBackend(loggerFactory.CreateLogger<WindowsFirewallBackend>());
            coordinator = new FirewallCoordinator(paths, backend,
                [sink => new WindowsEventLogMonitor(sink, loggerFactory.CreateLogger<WindowsEventLogMonitor>())],
                loggerFactory, http, ServiceConstants.Version);

            await coordinator.StartAsync(stoppingToken).ConfigureAwait(false);

            if (coordinator.Settings.General.EnsureLogonFailureAuditing)
            {
                var warning = AuditPolicy.EnsureLogonFailureAuditing(logger);
                if (warning is not null)
                {
                    coordinator.AddStartupWarning(warning);
                }
            }

            server = new IpcServer(IpcCommands.PipeName, new CoordinatorRequestHandler(coordinator), loggerFactory.CreateLogger<IpcServer>(),
                PipeSecurityFactory.CreatePipe, PipeSecurityFactory.Identify);
            var serverRef = server;
            coordinator.ActivityPublished += entry => serverRef.Broadcast(IpcCommands.EventActivity, entry);
            coordinator.StatusChanged += status => serverRef.Broadcast(IpcCommands.EventStatus, status);
            server.Start();

            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "TheFirewall service failed");

            // A non-zero exit code lets the Service Control Manager apply the recovery (restart) actions.
            Environment.ExitCode = 1;
            lifetime.StopApplication();
        }
        finally
        {
            if (server is not null)
            {
                await server.DisposeAsync().ConfigureAwait(false);
            }

            if (coordinator is not null)
            {
                await coordinator.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static HttpClient CreateHttpClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("TheFirewall", ServiceConstants.Version));
        return http;
    }
}
