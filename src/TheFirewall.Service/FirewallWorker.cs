using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
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

    // Held for the life of the process so a second copy cannot run against the same data and firewall rules.
    private static Mutex? instanceMutex;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        FirewallCoordinator? coordinator = null;
        IpcServer? server = null;
        using var http = CreateHttpClient();
        if (!AcquireInstance())
        {
            logger.LogCritical("Another TheFirewall service process is already running (perhaps TheFirewall.Service.exe was started by hand). Stop it and start the Windows service instead.");
            Environment.ExitCode = 2;
            lifetime.StopApplication();
            return;
        }

        try
        {
            var paths = FirewallPaths.Default;
            var backend = new WindowsFirewallBackend(loggerFactory.CreateLogger<WindowsFirewallBackend>());
            coordinator = new FirewallCoordinator(paths, backend,
                [sink => new WindowsEventLogMonitor(sink, loggerFactory.CreateLogger<WindowsEventLogMonitor>())],
                loggerFactory, http, ServiceConstants.Version);

            await coordinator.StartAsync(stoppingToken).ConfigureAwait(false);

            using (var self = WindowsIdentity.GetCurrent())
            {
                if (!self.IsSystem)
                {
                    coordinator.AddStartupWarning(WindowsServiceHelpers.IsWindowsService()
                        ? $"The TheFirewall service runs as {self.Name} instead of Local System, so it may be unable to read the Security log or change firewall rules."
                        : "TheFirewall.Service.exe is running as an ordinary program instead of the Windows service. Close it and open TheFirewall.exe, which installs and starts the service.");
                }
            }

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
            coordinator.ActivityChanged += entry => serverRef.Broadcast(IpcCommands.EventActivityUpdated, entry);
            coordinator.ActivityDeleted += ids => serverRef.Broadcast(IpcCommands.EventActivityRemoved, new ActivityRemovedEvent { Ids = [.. ids] });
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

    private static bool AcquireInstance()
    {
        try
        {
            instanceMutex = new Mutex(false, @"Global\TheFirewall.Service.Instance");
            try
            {
                return instanceMutex.WaitOne(0);
            }
            catch (AbandonedMutexException)
            {
                return true; // the previous service process ended without releasing it
            }
        }
        catch (UnauthorizedAccessException)
        {
            return false; // created by another (SYSTEM) instance
        }
    }

    private static HttpClient CreateHttpClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("TheFirewall", ServiceConstants.Version));
        return http;
    }
}
