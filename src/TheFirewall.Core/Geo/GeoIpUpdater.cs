using System.Globalization;
using Microsoft.Extensions.Logging;

namespace TheFirewall.Core.Geo;

/// <summary>Downloads the monthly DB-IP country lite database.</summary>
public sealed class GeoIpUpdater(HttpClient http, ILogger logger, TimeProvider? time = null)
{
    public const string FileName = "dbip-country-lite.csv.gz";
    private const string VersionFileName = "dbip-country-lite.version";
    private const string UrlFormat = "https://download.db-ip.com/free/dbip-country-lite-{0:yyyy}-{0:MM}.csv.gz";

    private readonly TimeProvider time = time ?? TimeProvider.System;

    public static string GetDatabasePath(string directory) => Path.Combine(directory, FileName);

    /// <summary>Returns the yyyy-MM version of the installed database, or null.</summary>
    public static string? GetInstalledVersion(string directory)
    {
        var path = Path.Combine(directory, VersionFileName);
        return File.Exists(path) ? File.ReadAllText(path).Trim() : null;
    }

    public bool IsUpdateDue(string directory)
    {
        var installed = GetInstalledVersion(directory);
        var current = time.GetUtcNow().ToString("yyyy-MM", CultureInfo.InvariantCulture);
        return installed is null || !File.Exists(GetDatabasePath(directory)) || string.CompareOrdinal(installed, current) < 0;
    }

    /// <summary>Downloads the newest available database. Returns the loaded database or null on failure.</summary>
    public async Task<GeoIpDatabase?> UpdateAsync(string directory, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(directory);
        var now = time.GetUtcNow();
        foreach (var month in new[] { now, now.AddMonths(-1) })
        {
            var url = string.Format(CultureInfo.InvariantCulture, UrlFormat, month.UtcDateTime);
            var temp = Path.Combine(directory, FileName + ".download");
            try
            {
                using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    logger.LogInformation("GeoIP database {Url} not available ({Status})", url, (int)response.StatusCode);
                    continue;
                }

                await using (var output = File.Create(temp))
                {
                    await response.Content.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
                }

                var version = month.ToString("yyyy-MM", CultureInfo.InvariantCulture);
                var database = GeoIpDatabase.Load(temp, new DateTimeOffset(month.Year, month.Month, 1, 0, 0, 0, TimeSpan.Zero));
                File.Move(temp, GetDatabasePath(directory), overwrite: true);
                await File.WriteAllTextAsync(Path.Combine(directory, VersionFileName), version, cancellationToken).ConfigureAwait(false);
                logger.LogInformation("GeoIP database updated to {Version} ({Ranges} ranges)", version, database.RangeCount);
                return database;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Unable to download GeoIP database from {Url}", url);
            }
            finally
            {
                try
                {
                    File.Delete(temp);
                }
                catch (IOException)
                {
                }
            }
        }

        return null;
    }

    public static GeoIpDatabase? TryLoadInstalled(string directory, ILogger logger)
    {
        var path = GetDatabasePath(directory);
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            var version = GetInstalledVersion(directory);
            DateTimeOffset? date = version is not null && DateTimeOffset.TryParseExact(version + "-01", "yyyy-MM-dd", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            return GeoIpDatabase.Load(path, date);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to load GeoIP database {Path}", path);
            return null;
        }
    }
}
