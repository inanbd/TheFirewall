using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;

namespace TheFirewall.Service;

/// <summary>Writes logs to %ProgramData%\TheFirewall\logs\service-yyyyMMdd.log and keeps two weeks of files.</summary>
internal sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly string directory;
    private readonly BlockingCollection<string> queue = new(10_000);
    private readonly Thread writer;

    public FileLoggerProvider(string directory)
    {
        this.directory = directory;
        Directory.CreateDirectory(directory);
        writer = new Thread(WriteLoop) { IsBackground = true, Name = "TheFirewall file logger" };
        writer.Start();
        CleanupOldFiles();
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    private void Enqueue(string line) => queue.TryAdd(line);

    private void WriteLoop()
    {
        foreach (var line in queue.GetConsumingEnumerable())
        {
            try
            {
                var path = Path.Combine(directory, $"service-{DateTime.Now:yyyyMMdd}.log");
                File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private void CleanupOldFiles()
    {
        try
        {
            foreach (var file in Directory.GetFiles(directory, "service-*.log"))
            {
                if (File.GetLastWriteTimeUtc(file) < DateTime.UtcNow.AddDays(-14))
                {
                    File.Delete(file);
                }
            }
        }
        catch (IOException)
        {
        }
    }

    public void Dispose()
    {
        queue.CompleteAdding();
        writer.Join(TimeSpan.FromSeconds(2));
    }

    private sealed class FileLogger(FileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var shortCategory = category[(category.LastIndexOf('.') + 1)..];
            var line = string.Create(CultureInfo.InvariantCulture,
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{logLevel.ToString()[..4].ToUpperInvariant()}] {shortCategory}: {formatter(state, exception)}");
            if (exception is not null)
            {
                line += Environment.NewLine + exception;
            }

            provider.Enqueue(line);
        }
    }
}
