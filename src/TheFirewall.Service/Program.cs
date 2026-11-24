using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using TheFirewall.Core;
using TheFirewall.Service;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("TheFirewall service runs on Windows only.");
    return 1;
}

if (args.Length > 0 && ServiceCli.Verbs.Contains(args[0], StringComparer.OrdinalIgnoreCase))
{
    return ServiceCli.Run(args);
}

// Started by hand (e.g. double-clicked) rather than by the Service Control Manager: install or start the real
// Windows service instead of running as an ordinary program without the rights it needs.
// "--console" still runs it in the foreground for troubleshooting.
bool console = args.Contains("--console", StringComparer.OrdinalIgnoreCase);
if (!console && !WindowsServiceHelpers.IsWindowsService())
{
    return ServiceCli.RunInteractive();
}

args = args.Where(a => !a.Equals("--console", StringComparison.OrdinalIgnoreCase)).ToArray();

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});

builder.Services.AddWindowsService(options => options.ServiceName = ServiceConstants.ServiceName);
builder.Services.Configure<EventLogSettings>(settings =>
{
    settings.SourceName = ServiceConstants.ServiceName;
    settings.LogName = "Application";
});
builder.Logging.AddFilter<EventLogLoggerProvider>(level => level >= LogLevel.Warning);
builder.Logging.AddProvider(new FileLoggerProvider(FirewallPaths.Default.LogsDirectory));
builder.Services.AddHostedService<FirewallWorker>();
builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(20));

var host = builder.Build();
await host.RunAsync();
return Environment.ExitCode;
