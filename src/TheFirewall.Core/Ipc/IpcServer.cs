using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace TheFirewall.Core.Ipc;

public sealed class IpcClientInfo
{
    /// <summary>True when the client process runs elevated as an administrator (or as SYSTEM).</summary>
    public bool IsAdministrator { get; set; }

    public string? UserName { get; set; }
}

public interface IIpcRequestHandler
{
    Task<object?> HandleAsync(string command, JsonElement? payload, IpcClientInfo client, CancellationToken cancellationToken);
}

/// <summary>Newline-delimited JSON request/response server over a named pipe, with server-pushed events.</summary>
public sealed class IpcServer : IAsyncDisposable
{
    private readonly string pipeName;
    private readonly IIpcRequestHandler handler;
    private readonly ILogger logger;
    private readonly Func<string, NamedPipeServerStream> pipeFactory;
    private readonly Func<NamedPipeServerStream, IpcClientInfo> identify;
    private readonly ConcurrentDictionary<Guid, Connection> connections = new();
    private readonly CancellationTokenSource shutdown = new();
    private Task? acceptLoop;

    public IpcServer(string pipeName, IIpcRequestHandler handler, ILogger logger,
        Func<string, NamedPipeServerStream>? pipeFactory = null, Func<NamedPipeServerStream, IpcClientInfo>? identify = null)
    {
        this.pipeName = pipeName;
        this.handler = handler;
        this.logger = logger;
        this.pipeFactory = pipeFactory ?? DefaultPipeFactory;
        this.identify = identify ?? (_ => new IpcClientInfo { IsAdministrator = true, UserName = Environment.UserName });
    }

    public int ConnectionCount => connections.Count;

    public static NamedPipeServerStream DefaultPipeFactory(string name) =>
        new(name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

    public void Start() => acceptLoop ??= Task.Run(AcceptLoopAsync);

    /// <summary>Sends an event to every client that subscribed.</summary>
    public void Broadcast(string eventType, object payload)
    {
        if (connections.IsEmpty)
        {
            return;
        }

        string line;
        try
        {
            line = JsonSerializer.Serialize(new IpcMessage { Id = 0, Type = eventType, Payload = JsonSerializer.SerializeToElement(payload, IpcJson.Options) }, IpcJson.Options);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to serialise event {Event}", eventType);
            return;
        }

        foreach (var connection in connections.Values)
        {
            if (connection.Subscribed)
            {
                try
                {
                    connection.Enqueue(line, isEvent: true);
                }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "Unable to queue event for a client");
                }
            }
        }
    }

    private async Task AcceptLoopAsync()
    {
        var token = shutdown.Token;
        while (!token.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = pipeFactory(pipeName);
                await pipe.WaitForConnectionAsync(token).ConfigureAwait(false);
                var connection = new Connection(pipe, this);
                connections[connection.Id] = connection;
                _ = connection.RunAsync(token).ContinueWith(_ => connections.TryRemove(connection.Id, out var _), TaskScheduler.Default);
                pipe = null;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Named pipe accept failed");
                await Task.Delay(500, CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                pipe?.Dispose();
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await shutdown.CancelAsync().ConfigureAwait(false);
        foreach (var connection in connections.Values)
        {
            connection.Close();
        }

        if (acceptLoop is not null)
        {
            try
            {
                await acceptLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        shutdown.Dispose();
    }

    private sealed class Connection(NamedPipeServerStream pipe, IpcServer server)
    {
        private const int MaxQueuedEvents = 5000;
        private readonly Channel<string> outgoing = Channel.CreateUnbounded<string>(); // multi-reader variant so Count is supported
        private IpcClientInfo? client;

        public Guid Id { get; } = Guid.NewGuid();

        public bool Subscribed { get; private set; }

        public void Enqueue(string line, bool isEvent)
        {
            if (isEvent && outgoing.Reader.Count > MaxQueuedEvents)
            {
                return; // slow client; drop events rather than grow without bound
            }

            outgoing.Writer.TryWrite(line);
        }

        public void Close()
        {
            outgoing.Writer.TryComplete();
            try
            {
                pipe.Dispose();
            }
            catch (IOException)
            {
            }
        }

        public async Task RunAsync(CancellationToken token)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token);
            var writer = Task.Run(() => WriteLoopAsync(linked.Token), CancellationToken.None);
            try
            {
                using var reader = new StreamReader(pipe, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
                while (!linked.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(linked.Token).ConfigureAwait(false);
                    if (line is null)
                    {
                        break;
                    }

                    if (line.Length == 0)
                    {
                        continue;
                    }

                    // Impersonation is only possible after data has been read from the pipe.
                    client ??= IdentifyClient();

                    IpcMessage? request;
                    try
                    {
                        request = JsonSerializer.Deserialize<IpcMessage>(line, IpcJson.Options);
                    }
                    catch (JsonException)
                    {
                        continue;
                    }

                    if (request is null)
                    {
                        continue;
                    }

                    _ = Task.Run(() => HandleAsync(request, client, linked.Token), CancellationToken.None);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (IOException)
            {
            }
            catch (Exception ex)
            {
                server.logger.LogDebug(ex, "Pipe connection ended with an error");
            }
            finally
            {
                await linked.CancelAsync().ConfigureAwait(false);
                outgoing.Writer.TryComplete();
                try
                {
                    await writer.ConfigureAwait(false);
                }
                catch (Exception)
                {
                }

                await pipe.DisposeAsync().ConfigureAwait(false);
            }
        }

        private IpcClientInfo IdentifyClient()
        {
            try
            {
                return server.identify(pipe);
            }
            catch (Exception ex)
            {
                server.logger.LogWarning(ex, "Unable to identify pipe client; treating it as read-only");
                return new IpcClientInfo();
            }
        }

        private async Task HandleAsync(IpcMessage request, IpcClientInfo info, CancellationToken token)
        {
            var response = new IpcMessage { Id = request.Id, Type = "response" };
            try
            {
                if (string.Equals(request.Type, IpcCommands.Subscribe, StringComparison.OrdinalIgnoreCase))
                {
                    Subscribed = true;
                }
                else if (IpcCommands.AdminCommands.Contains(request.Type) && !info.IsAdministrator)
                {
                    throw new IpcException("Administrator permission is required. Restart TheFirewall as administrator to make changes.",
                        IpcErrorCodes.ElevationRequired);
                }
                else
                {
                    var result = await server.handler.HandleAsync(request.Type, request.Payload, info, token).ConfigureAwait(false);
                    if (result is not null)
                    {
                        response.Payload = JsonSerializer.SerializeToElement(result, result.GetType(), IpcJson.Options);
                    }
                }
            }
            catch (IpcException ex)
            {
                response.Ok = false;
                response.Error = ex.Message;
                response.ErrorCode = ex.Code;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or FormatException)
            {
                response.Ok = false;
                response.Error = ex.Message;
                response.ErrorCode = IpcErrorCodes.Invalid;
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                server.logger.LogError(ex, "Request {Command} failed", request.Type);
                response.Ok = false;
                response.Error = "The service could not complete the request: " + ex.Message;
                response.ErrorCode = IpcErrorCodes.Internal;
            }

            Enqueue(JsonSerializer.Serialize(response, IpcJson.Options), isEvent: false);
        }

        private async Task WriteLoopAsync(CancellationToken token)
        {
            var encoding = new UTF8Encoding(false);
            try
            {
                await foreach (var line in outgoing.Reader.ReadAllAsync(token).ConfigureAwait(false))
                {
                    var bytes = encoding.GetBytes(line + "\n");
                    await pipe.WriteAsync(bytes, token).ConfigureAwait(false);
                    await pipe.FlushAsync(token).ConfigureAwait(false);
                }
            }
            catch (Exception) when (token.IsCancellationRequested || !pipe.IsConnected)
            {
            }
            catch (IOException)
            {
            }
        }
    }
}
