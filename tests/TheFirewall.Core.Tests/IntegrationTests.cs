using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Firewall;
using TheFirewall.Core.Ipc;
using TheFirewall.Core.Monitoring;
using TheFirewall.Core.Service;

namespace TheFirewall.Core.Tests;

public sealed class IntegrationTests
{
    private sealed class NoNetworkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
    }

    [Fact]
    public async Task Coordinator_bans_through_the_pipe_and_writes_firewall_rules()
    {
        using var dir = new TempDirectory();
        var backend = new InMemoryFirewallBackend();
        using var http = new HttpClient(new NoNetworkHandler());
        var coordinator = new FirewallCoordinator(new FirewallPaths(dir.Path), backend, [], NullLoggerFactory.Instance, http, "1.0.0-test");
        await coordinator.StartAsync(TestContext.Current.CancellationToken);

        var pipeName = "thefirewall-test-" + Guid.NewGuid().ToString("N")[..8];
        await using var server = new IpcServer(pipeName, new CoordinatorRequestHandler(coordinator), NullLogger.Instance);
        coordinator.ActivityPublished += entry => server.Broadcast(IpcCommands.EventActivity, entry);
        server.Start();

        await using var client = new IpcClient(pipeName);
        await client.ConnectAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var received = new List<ActivityEntry>();
        var bannedSeen = new TaskCompletionSource();
        client.EventReceived += (type, payload) =>
        {
            if (type == IpcCommands.EventActivity)
            {
                var entry = payload.Deserialize<ActivityEntry>(IpcJson.Options)!;
                lock (received)
                {
                    received.Add(entry);
                }

                if (entry.Type == ActivityType.Banned)
                {
                    bannedSeen.TrySetResult();
                }
            }
        };
        await client.RequestAsync(IpcCommands.Subscribe, cancellationToken: TestContext.Current.CancellationToken);

        var hello = await client.RequestAsync<HelloResponse>(IpcCommands.Hello, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("1.0.0-test", hello!.ServiceVersion);

        for (int i = 0; i < 5; i++)
        {
            coordinator.Submit(new LoginEvent { IPAddress = "203.0.113.25", Source = "RDP", UserName = "admin", Timestamp = DateTimeOffset.UtcNow.AddSeconds(-30 + (i * 2)) });
        }

        try
        {
            await bannedSeen.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        }
        catch (TimeoutException)
        {
            var recent = coordinator.QueryActivity(new ActivityQuery { Limit = 20 });
            Assert.Fail("No ban. Activity: " + string.Join(" | ", recent.Select(r => $"{r.Type} {r.IPAddress} {r.Message}")) +
                        " Received: " + string.Join(" | ", received.Select(r => $"{r.Type} {r.Message}")));
        }

        // The cycle loop picks up the ban request and writes the rule.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!backend.Rules.ContainsKey("TheFirewall_Ban_0000") && DateTime.UtcNow < deadline)
        {
            await Task.Delay(100, TestContext.Current.CancellationToken);
        }

        Assert.Equal("203.0.113.25", backend.Rules["TheFirewall_Ban_0000"].RemoteAddresses);

        var bans = await client.RequestAsync<List<IPRecord>>(IpcCommands.Bans, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("203.0.113.25", Assert.Single(bans!).IPAddress);

        var stats = await client.RequestAsync<DashboardStats>(IpcCommands.Stats, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(5, stats!.FailedLast24h);

        // Settings round trip through the pipe, including validation errors.
        var settings = await client.RequestAsync<FirewallSettings>(IpcCommands.GetSettings, cancellationToken: TestContext.Current.CancellationToken);
        settings!.Blacklist.Add(new AddressEntry { Value = "nonsense" });
        var save = await client.RequestAsync<SaveSettingsResponse>(IpcCommands.SaveSettings, settings, TestContext.Current.CancellationToken);
        Assert.False(save!.Saved);
        Assert.NotEmpty(save.Errors);

        settings.Blacklist.Clear();
        settings.Blacklist.Add(new AddressEntry { Value = "198.51.100.0/24" });
        save = await client.RequestAsync<SaveSettingsResponse>(IpcCommands.SaveSettings, settings, TestContext.Current.CancellationToken);
        Assert.True(save!.Saved);
        Assert.Equal("198.51.100.0/24", backend.Rules["TheFirewall_Blacklist_0000"].RemoteAddresses);

        await client.RequestAsync(IpcCommands.Unban, new UnbanRequest { IPAddresses = ["203.0.113.25"], AddToWhitelist = true }, TestContext.Current.CancellationToken);
        Assert.False(backend.Rules.ContainsKey("TheFirewall_Ban_0000"));
        var lookup = await client.RequestAsync<LookupResult>(IpcCommands.Lookup, new LookupRequest { IPAddress = "203.0.113.25" }, TestContext.Current.CancellationToken);
        Assert.True(lookup!.IsWhitelisted);
        Assert.NotEmpty(lookup.RecentActivity);

        var sources = await client.RequestAsync<List<SourceInfoDto>>(IpcCommands.Sources, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Contains(sources!, s => s.Definition.Id == "rdp-logon" && s.IsBuiltIn);

        var test = await client.RequestAsync<SourceTestResult>(IpcCommands.TestSource, new SourceTestRequest
        {
            Definition = BuiltInSources.Find("rdp-logon")!,
            Sample = EventXmlMatcherTests.Rdp4625,
        }, TestContext.Current.CancellationToken);
        Assert.Equal("45.141.84.10", Assert.Single(test!.Matches).IPAddress);

        var unknown = await Assert.ThrowsAsync<IpcException>(() => client.RequestAsync("nope", cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(IpcErrorCodes.NotFound, unknown.Code);

        lock (received)
        {
            Assert.Contains(received, r => r.Type == ActivityType.FailedLogin);
        }

        await coordinator.DisposeAsync();
    }

    [Fact]
    public async Task Non_admin_clients_are_read_only()
    {
        var pipeName = "thefirewall-test-" + Guid.NewGuid().ToString("N")[..8];
        await using var server = new IpcServer(pipeName, new EchoHandler(), NullLogger.Instance, identify: _ => new IpcClientInfo { IsAdministrator = false });
        server.Start();
        await using var client = new IpcClient(pipeName);
        await client.ConnectAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Equal("ok", await client.RequestAsync<string>(IpcCommands.Status, cancellationToken: TestContext.Current.CancellationToken));
        var ex = await Assert.ThrowsAsync<IpcException>(() => client.RequestAsync(IpcCommands.SaveSettings, new FirewallSettings(), TestContext.Current.CancellationToken));
        Assert.Equal(IpcErrorCodes.ElevationRequired, ex.Code);
    }

    private sealed class EchoHandler : IIpcRequestHandler
    {
        public Task<object?> HandleAsync(string command, JsonElement? payload, IpcClientInfo client, CancellationToken cancellationToken) =>
            Task.FromResult<object?>("ok");
    }
}
