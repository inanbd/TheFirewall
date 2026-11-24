using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace TheFirewall.Core.Ipc;

/// <summary>Client side of the service pipe. Thread-safe; supports concurrent requests and pushed events.</summary>
public sealed class IpcClient : IAsyncDisposable
{
    private readonly string pipeName;
    private readonly ConcurrentDictionary<long, TaskCompletionSource<IpcMessage>> pending = new();
    private readonly SemaphoreSlim writeLock = new(1, 1);
    private NamedPipeClientStream? pipe;
    private CancellationTokenSource? readCancellation;
    private long nextId;
    private int disconnected;

    public IpcClient(string pipeName = IpcCommands.PipeName)
    {
        this.pipeName = pipeName;
    }

    public bool IsConnected => pipe?.IsConnected == true && Volatile.Read(ref disconnected) == 0;

    /// <summary>Raised on a background thread for every pushed event (event type, payload).</summary>
    public event Action<string, JsonElement>? EventReceived;

    /// <summary>Raised once when the connection is lost.</summary>
    public event Action? Disconnected;

    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromMinutes(2);

    public async Task ConnectAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        // Identification lets the service check who we are (and whether we are elevated) without being able to act as us.
        var level = OperatingSystem.IsWindows() ? TokenImpersonationLevel.Identification : TokenImpersonationLevel.None;
        var stream = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, level);
        try
        {
            await stream.ConnectAsync((int)timeout.TotalMilliseconds, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        pipe = stream;
        Volatile.Write(ref disconnected, 0);
        readCancellation = new CancellationTokenSource();
        _ = Task.Run(() => ReadLoopAsync(stream, readCancellation.Token), CancellationToken.None);
    }

    public async Task<T?> RequestAsync<T>(string command, object? payload = null, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(command, payload, cancellationToken).ConfigureAwait(false);
        return response.Payload is { } element && element.ValueKind != JsonValueKind.Null
            ? element.Deserialize<T>(IpcJson.Options)
            : default;
    }

    public async Task RequestAsync(string command, object? payload = null, CancellationToken cancellationToken = default) =>
        await SendAsync(command, payload, cancellationToken).ConfigureAwait(false);

    private async Task<IpcMessage> SendAsync(string command, object? payload, CancellationToken cancellationToken)
    {
        var stream = pipe;
        if (stream is null || !IsConnected)
        {
            throw new IOException("Not connected to the TheFirewall service.");
        }

        long id = Interlocked.Increment(ref nextId);
        var completion = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        pending[id] = completion;
        try
        {
            var message = new IpcMessage
            {
                Id = id,
                Type = command,
                Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, payload.GetType(), IpcJson.Options),
            };
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(message, IpcJson.Options) + "\n");
            await writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                writeLock.Release();
            }

            var response = await completion.Task.WaitAsync(RequestTimeout, cancellationToken).ConfigureAwait(false);
            if (!response.Ok)
            {
                throw new IpcException(response.Error ?? "The request failed.", response.ErrorCode ?? IpcErrorCodes.Internal);
            }

            return response;
        }
        catch (TimeoutException)
        {
            throw new IOException("The TheFirewall service did not answer in time.");
        }
        finally
        {
            pending.TryRemove(id, out _);
        }
    }

    private async Task ReadLoopAsync(NamedPipeClientStream stream, CancellationToken token)
    {
        try
        {
            using var reader = new StreamReader(stream, new UTF8Encoding(false), false, 4096, leaveOpen: true);
            while (!token.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(token).ConfigureAwait(false);
                if (line is null)
                {
                    break;
                }

                IpcMessage? message;
                try
                {
                    message = JsonSerializer.Deserialize<IpcMessage>(line, IpcJson.Options);
                }
                catch (JsonException)
                {
                    continue;
                }

                if (message is null)
                {
                    continue;
                }

                if (message.Id != 0 && pending.TryRemove(message.Id, out var completion))
                {
                    completion.TrySetResult(message);
                }
                else if (message.Id == 0 && message.Payload is { } payload)
                {
                    try
                    {
                        EventReceived?.Invoke(message.Type, payload);
                    }
                    catch (Exception)
                    {
                        // Listener errors must not kill the connection.
                    }
                }
            }
        }
        catch (Exception)
        {
            // Connection lost.
        }
        finally
        {
            OnDisconnected();
        }
    }

    private void OnDisconnected()
    {
        if (Interlocked.Exchange(ref disconnected, 1) == 1)
        {
            return;
        }

        foreach (var (_, completion) in pending)
        {
            completion.TrySetException(new IOException("The connection to the TheFirewall service was lost."));
        }

        pending.Clear();
        Disconnected?.Invoke();
    }

    public async ValueTask DisposeAsync()
    {
        if (readCancellation is not null)
        {
            await readCancellation.CancelAsync().ConfigureAwait(false);
        }

        if (pipe is not null)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
        }

        OnDisconnected();
        readCancellation?.Dispose();
        writeLock.Dispose();
    }
}
