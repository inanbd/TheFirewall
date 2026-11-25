using System.Globalization;
using Microsoft.Data.Sqlite;
using TheFirewall.Core.Monitoring;

namespace TheFirewall.Core.Data;

/// <summary>SQLite storage for address state, activity history, file positions and firewall rule fingerprints.</summary>
public sealed class FirewallDatabase : IFilePositionStore, IDisposable
{
    private readonly SqliteConnection connection;
    private readonly object sync = new();

    public FirewallDatabase(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var builder = new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false };
        connection = new SqliteConnection(builder.ToString());
        connection.Open();
        Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;");
        CreateSchema();
    }

    private void CreateSchema()
    {
        Execute("""
            CREATE TABLE IF NOT EXISTS ip_state(
                ip TEXT PRIMARY KEY NOT NULL,
                failed_count INTEGER NOT NULL DEFAULT 0,
                first_failed INTEGER NULL,
                last_failed INTEGER NULL,
                last_activity INTEGER NOT NULL,
                is_banned INTEGER NOT NULL DEFAULT 0,
                ban_start INTEGER NULL,
                ban_end INTEGER NULL,
                ban_level INTEGER NOT NULL DEFAULT 0,
                source TEXT NULL,
                user_names TEXT NULL,
                last_log TEXT NULL,
                ban_reason TEXT NULL,
                manual INTEGER NOT NULL DEFAULT 0,
                country TEXT NULL);
            CREATE INDEX IF NOT EXISTS ix_ip_state_banned ON ip_state(is_banned, ban_end);
            CREATE INDEX IF NOT EXISTS ix_ip_state_activity ON ip_state(last_activity);

            CREATE TABLE IF NOT EXISTS activity(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time INTEGER NOT NULL,
                type INTEGER NOT NULL,
                ip TEXT NULL,
                country TEXT NULL,
                source TEXT NULL,
                user_name TEXT NULL,
                message TEXT NULL);
            CREATE INDEX IF NOT EXISTS ix_activity_time ON activity(time);
            CREATE INDEX IF NOT EXISTS ix_activity_type_time ON activity(type, time);

            CREATE TABLE IF NOT EXISTS file_positions(path TEXT PRIMARY KEY NOT NULL, position INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS firewall_rules(name TEXT PRIMARY KEY NOT NULL, hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY NOT NULL, value TEXT NULL);
            """);
    }

    // ------------------------------------------------------------------ IP state

    public IPRecord? GetRecord(string ip)
    {
        lock (sync)
        {
            using var cmd = Command("SELECT * FROM ip_state WHERE ip = $ip", ("$ip", ip));
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? ReadRecord(reader) : null;
        }
    }

    public void SaveRecord(IPRecord r)
    {
        lock (sync)
        {
            using var cmd = Command("""
                INSERT INTO ip_state(ip, failed_count, first_failed, last_failed, last_activity, is_banned, ban_start, ban_end,
                                     ban_level, source, user_names, last_log, ban_reason, manual, country)
                VALUES($ip, $fc, $ff, $lf, $la, $b, $bs, $be, $bl, $src, $users, $log, $reason, $manual, $country)
                ON CONFLICT(ip) DO UPDATE SET failed_count=$fc, first_failed=$ff, last_failed=$lf, last_activity=$la,
                    is_banned=$b, ban_start=$bs, ban_end=$be, ban_level=$bl, source=$src, user_names=$users, last_log=$log,
                    ban_reason=$reason, manual=$manual, country=$country
                """,
                ("$ip", r.IPAddress), ("$fc", r.FailedCount), ("$ff", ToDb(r.FirstFailedUtc)), ("$lf", ToDb(r.LastFailedUtc)),
                ("$la", ToDb(r.LastActivityUtc)), ("$b", r.IsBanned ? 1 : 0), ("$bs", ToDb(r.BanStartUtc)), ("$be", ToDb(r.BanEndUtc)),
                ("$bl", r.BanLevel), ("$src", r.Source), ("$users", r.UserNames), ("$log", Truncate(r.LastLog, 500)),
                ("$reason", Truncate(r.BanReason, 500)), ("$manual", r.Manual ? 1 : 0), ("$country", r.Country));
            cmd.ExecuteNonQuery();
        }
    }

    public void DeleteRecord(string ip)
    {
        lock (sync)
        {
            using var cmd = Command("DELETE FROM ip_state WHERE ip = $ip", ("$ip", ip));
            cmd.ExecuteNonQuery();
        }
    }

    public List<IPRecord> GetBannedRecords() => QueryRecords("SELECT * FROM ip_state WHERE is_banned = 1 ORDER BY ban_start DESC");

    public List<string> GetBannedAddresses()
    {
        lock (sync)
        {
            using var cmd = Command("SELECT ip FROM ip_state WHERE is_banned = 1");
            using var reader = cmd.ExecuteReader();
            var list = new List<string>();
            while (reader.Read())
            {
                list.Add(reader.GetString(0));
            }

            return list;
        }
    }

    public List<IPRecord> GetExpiredBans(DateTimeOffset now) =>
        QueryRecords("SELECT * FROM ip_state WHERE is_banned = 1 AND ban_end IS NOT NULL AND ban_end <= $now", ("$now", ToDb(now)));

    /// <summary>Addresses with failed attempts that are not (yet) banned.</summary>
    public List<IPRecord> GetWatchedRecords(int limit = 1000) =>
        QueryRecords("SELECT * FROM ip_state WHERE is_banned = 0 AND failed_count > 0 ORDER BY last_failed DESC LIMIT $limit", ("$limit", limit));

    /// <summary>Removes addresses that are not banned and have been quiet for long enough.</summary>
    public int ForgetQuietAddresses(DateTimeOffset failedCutoff, DateTimeOffset repeatOffenderCutoff)
    {
        lock (sync)
        {
            using var cmd = Command("""
                DELETE FROM ip_state WHERE is_banned = 0 AND (
                    (ban_level = 0 AND last_activity < $failedCutoff) OR
                    (ban_level > 0 AND last_activity < $repeatCutoff))
                """, ("$failedCutoff", ToDb(failedCutoff)), ("$repeatCutoff", ToDb(repeatOffenderCutoff)));
            int deleted = cmd.ExecuteNonQuery();

            // Reset counters that are outside the window but kept for escalation history.
            using var reset = Command("UPDATE ip_state SET failed_count = 0 WHERE is_banned = 0 AND failed_count > 0 AND last_failed < $failedCutoff",
                ("$failedCutoff", ToDb(failedCutoff)));
            reset.ExecuteNonQuery();
            return deleted;
        }
    }

    public int ClearAllBans()
    {
        lock (sync)
        {
            using var cmd = Command("UPDATE ip_state SET is_banned = 0, ban_start = NULL, ban_end = NULL, failed_count = 0 WHERE is_banned = 1");
            return cmd.ExecuteNonQuery();
        }
    }

    private List<IPRecord> QueryRecords(string sql, params (string Name, object? Value)[] parameters)
    {
        lock (sync)
        {
            using var cmd = Command(sql, parameters);
            using var reader = cmd.ExecuteReader();
            var list = new List<IPRecord>();
            while (reader.Read())
            {
                list.Add(ReadRecord(reader));
            }

            return list;
        }
    }

    private static IPRecord ReadRecord(SqliteDataReader r) => new()
    {
        IPAddress = r.GetString(r.GetOrdinal("ip")),
        FailedCount = r.GetInt32(r.GetOrdinal("failed_count")),
        FirstFailedUtc = FromDb(r, "first_failed"),
        LastFailedUtc = FromDb(r, "last_failed"),
        LastActivityUtc = FromDb(r, "last_activity") ?? DateTimeOffset.UnixEpoch,
        IsBanned = r.GetInt32(r.GetOrdinal("is_banned")) != 0,
        BanStartUtc = FromDb(r, "ban_start"),
        BanEndUtc = FromDb(r, "ban_end"),
        BanLevel = r.GetInt32(r.GetOrdinal("ban_level")),
        Source = GetString(r, "source"),
        UserNames = GetString(r, "user_names"),
        LastLog = GetString(r, "last_log"),
        BanReason = GetString(r, "ban_reason"),
        Manual = r.GetInt32(r.GetOrdinal("manual")) != 0,
        Country = GetString(r, "country"),
    };

    // ------------------------------------------------------------------ Activity

    public long AddActivity(ActivityEntry entry)
    {
        lock (sync)
        {
            using var cmd = Command("""
                INSERT INTO activity(time, type, ip, country, source, user_name, message)
                VALUES($time, $type, $ip, $country, $source, $user, $message);
                SELECT last_insert_rowid();
                """,
                ("$time", ToDb(entry.TimeUtc)), ("$type", (int)entry.Type), ("$ip", entry.IPAddress), ("$country", entry.Country),
                ("$source", entry.Source), ("$user", Truncate(entry.UserName, 200)), ("$message", Truncate(entry.Message, 1000)));
            entry.Id = Convert.ToInt64(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
            return entry.Id;
        }
    }

    public List<ActivityEntry> QueryActivity(ActivityQuery query)
    {
        var sql = new System.Text.StringBuilder("SELECT id, time, type, ip, country, source, user_name, message FROM activity WHERE 1=1");
        var parameters = new List<(string, object?)>();
        if (query.SinceUtc is { } since)
        {
            sql.Append(" AND time >= $since");
            parameters.Add(("$since", ToDb(since)));
        }

        if (query.BeforeId is { } beforeId)
        {
            sql.Append(" AND id < $before");
            parameters.Add(("$before", beforeId));
        }

        if (query.Types is { Count: > 0 } types)
        {
            sql.Append(" AND type IN (").Append(string.Join(',', types.Select(t => ((int)t).ToString(CultureInfo.InvariantCulture)))).Append(')');
        }

        if (!string.IsNullOrWhiteSpace(query.IPAddress))
        {
            sql.Append(" AND ip = $ip");
            parameters.Add(("$ip", query.IPAddress.Trim()));
        }

        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            sql.Append(" AND (ip LIKE $search OR source LIKE $search OR user_name LIKE $search OR message LIKE $search OR country LIKE $search)");
            parameters.Add(("$search", "%" + query.Search.Trim() + "%"));
        }

        sql.Append(" ORDER BY id DESC LIMIT $limit");
        parameters.Add(("$limit", Math.Clamp(query.Limit, 1, 5000)));

        lock (sync)
        {
            using var cmd = Command(sql.ToString(), [.. parameters]);
            using var reader = cmd.ExecuteReader();
            var list = new List<ActivityEntry>();
            while (reader.Read())
            {
                list.Add(new ActivityEntry
                {
                    Id = reader.GetInt64(0),
                    TimeUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(1)),
                    Type = (ActivityType)reader.GetInt32(2),
                    IPAddress = reader.IsDBNull(3) ? null : reader.GetString(3),
                    Country = reader.IsDBNull(4) ? null : reader.GetString(4),
                    Source = reader.IsDBNull(5) ? null : reader.GetString(5),
                    UserName = reader.IsDBNull(6) ? null : reader.GetString(6),
                    Message = reader.IsDBNull(7) ? null : reader.GetString(7),
                });
            }

            return list;
        }
    }

    public void UpdateActivityUserName(long id, string userName)
    {
        lock (sync)
        {
            using var cmd = Command("UPDATE activity SET user_name = $user WHERE id = $id", ("$user", Truncate(userName, 200)), ("$id", id));
            cmd.ExecuteNonQuery();
        }
    }

    public int DeleteActivity(IEnumerable<long> ids)
    {
        var list = ids.Distinct().ToList();
        if (list.Count == 0)
        {
            return 0;
        }

        lock (sync)
        {
            using var cmd = Command($"DELETE FROM activity WHERE id IN ({string.Join(',', list.Select(i => i.ToString(CultureInfo.InvariantCulture)))})");
            return cmd.ExecuteNonQuery();
        }
    }

    public int PruneActivity(DateTimeOffset before)
    {
        lock (sync)
        {
            using var cmd = Command("DELETE FROM activity WHERE time < $before", ("$before", ToDb(before)));
            return cmd.ExecuteNonQuery();
        }
    }

    public DashboardStats GetDashboardStats(DateTimeOffset now)
    {
        var stats = new DashboardStats();
        long nowMs = now.ToUnixTimeMilliseconds();
        long dayAgo = nowMs - (long)TimeSpan.FromHours(24).TotalMilliseconds;
        long hourMs = (long)TimeSpan.FromHours(1).TotalMilliseconds;
        long dayMs = (long)TimeSpan.FromDays(1).TotalMilliseconds;
        long currentHourStart = nowMs - (nowMs % hourMs);
        long hourlyStart = currentHourStart - (23 * hourMs);
        long currentDayStart = nowMs - (nowMs % dayMs);
        long dailyStart = currentDayStart - (29 * dayMs);

        lock (sync)
        {
            stats.FailedLast24h = Scalar("SELECT COUNT(*) FROM activity WHERE type = 1 AND time >= $t", ("$t", dayAgo));
            stats.BansLast24h = Scalar("SELECT COUNT(*) FROM activity WHERE type = 3 AND time >= $t", ("$t", dayAgo));
            stats.SuccessfulLast24h = Scalar("SELECT COUNT(*) FROM activity WHERE type = 2 AND time >= $t", ("$t", dayAgo));
            stats.ActiveBans = Scalar("SELECT COUNT(*) FROM ip_state WHERE is_banned = 1");
            stats.WatchedAddresses = Scalar("SELECT COUNT(*) FROM ip_state WHERE is_banned = 0 AND failed_count > 0");
            stats.TotalBansAllTime = long.TryParse(GetMetaUnlocked("total_bans"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var total) ? total : 0;

            stats.HourlyFailed = Buckets(1, hourlyStart, hourMs, 24);
            stats.HourlyBans = Buckets(3, hourlyStart, hourMs, 24);
            stats.DailyFailed = Buckets(1, dailyStart, dayMs, 30);

            stats.TopSources = TopCounts("source", dayAgo);
            stats.TopCountries = TopCounts("country", dayAgo);
            stats.TopUserNames = TopCounts("user_name", dayAgo);
            stats.TopAddresses = TopCounts("ip", dayAgo);
        }

        return stats;
    }

    private List<long> Buckets(int type, long start, long size, int count)
    {
        var buckets = new long[count];
        using var cmd = Command("SELECT (time - $start) / $size AS b, COUNT(*) FROM activity WHERE type = $type AND time >= $start GROUP BY b",
            ("$start", start), ("$size", size), ("$type", type));
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            long index = reader.GetInt64(0);
            if (index >= 0 && index < count)
            {
                buckets[index] = reader.GetInt64(1);
            }
        }

        return [.. buckets];
    }

    private List<NamedCount> TopCounts(string column, long since)
    {
        using var cmd = Command($"SELECT {column}, COUNT(*) AS c FROM activity WHERE type = 1 AND time >= $t AND {column} IS NOT NULL AND {column} <> '' GROUP BY {column} ORDER BY c DESC LIMIT 8",
            ("$t", since));
        using var reader = cmd.ExecuteReader();
        var list = new List<NamedCount>();
        while (reader.Read())
        {
            list.Add(new NamedCount { Name = reader.GetString(0), Count = reader.GetInt64(1) });
        }

        return list;
    }

    public void IncrementTotalBans()
    {
        lock (sync)
        {
            long current = long.TryParse(GetMetaUnlocked("total_bans"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;
            SetMetaUnlocked("total_bans", (current + 1).ToString(CultureInfo.InvariantCulture));
        }
    }

    // ------------------------------------------------------------------ File positions

    public IReadOnlyDictionary<string, long> LoadFilePositions()
    {
        lock (sync)
        {
            using var cmd = Command("SELECT path, position FROM file_positions");
            using var reader = cmd.ExecuteReader();
            var map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            while (reader.Read())
            {
                map[reader.GetString(0)] = reader.GetInt64(1);
            }

            return map;
        }
    }

    public void SaveFilePositions(IReadOnlyDictionary<string, long> positions)
    {
        lock (sync)
        {
            using var tx = connection.BeginTransaction();
            using (var clear = Command("DELETE FROM file_positions"))
            {
                clear.Transaction = tx;
                clear.ExecuteNonQuery();
            }

            using var insert = Command("INSERT INTO file_positions(path, position) VALUES($p, $pos)");
            insert.Transaction = tx;
            var p = insert.Parameters.Add("$p", SqliteType.Text);
            var pos = insert.Parameters.Add("$pos", SqliteType.Integer);
            foreach (var (path, position) in positions)
            {
                p.Value = path;
                pos.Value = position;
                insert.ExecuteNonQuery();
            }

            tx.Commit();
        }
    }

    // ------------------------------------------------------------------ Firewall rule fingerprints

    public Dictionary<string, string> GetRuleHashes()
    {
        lock (sync)
        {
            using var cmd = Command("SELECT name, hash FROM firewall_rules");
            using var reader = cmd.ExecuteReader();
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            while (reader.Read())
            {
                map[reader.GetString(0)] = reader.GetString(1);
            }

            return map;
        }
    }

    public void ReplaceRuleHashes(IReadOnlyDictionary<string, string> hashes)
    {
        lock (sync)
        {
            using var tx = connection.BeginTransaction();
            using (var clear = Command("DELETE FROM firewall_rules"))
            {
                clear.Transaction = tx;
                clear.ExecuteNonQuery();
            }

            using var insert = Command("INSERT INTO firewall_rules(name, hash) VALUES($n, $h)");
            insert.Transaction = tx;
            var n = insert.Parameters.Add("$n", SqliteType.Text);
            var h = insert.Parameters.Add("$h", SqliteType.Text);
            foreach (var (name, hash) in hashes)
            {
                n.Value = name;
                h.Value = hash;
                insert.ExecuteNonQuery();
            }

            tx.Commit();
        }
    }

    // ------------------------------------------------------------------ Meta

    public string? GetMeta(string key)
    {
        lock (sync)
        {
            return GetMetaUnlocked(key);
        }
    }

    public void SetMeta(string key, string? value)
    {
        lock (sync)
        {
            SetMetaUnlocked(key, value);
        }
    }

    private string? GetMetaUnlocked(string key)
    {
        using var cmd = Command("SELECT value FROM meta WHERE key = $k", ("$k", key));
        return cmd.ExecuteScalar() as string;
    }

    private void SetMetaUnlocked(string key, string? value)
    {
        using var cmd = Command("INSERT INTO meta(key, value) VALUES($k, $v) ON CONFLICT(key) DO UPDATE SET value = $v", ("$k", key), ("$v", value));
        cmd.ExecuteNonQuery();
    }

    // ------------------------------------------------------------------ Helpers

    private void Execute(string sql)
    {
        lock (sync)
        {
            using var cmd = Command(sql);
            cmd.ExecuteNonQuery();
        }
    }

    private long Scalar(string sql, params (string Name, object? Value)[] parameters)
    {
        using var cmd = Command(sql, parameters);
        return Convert.ToInt64(cmd.ExecuteScalar() ?? 0L, CultureInfo.InvariantCulture);
    }

    private SqliteCommand Command(string sql, params (string Name, object? Value)[] parameters)
    {
        var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        return cmd;
    }

    private static object? ToDb(DateTimeOffset? value) => value?.ToUnixTimeMilliseconds();

    private static DateTimeOffset? FromDb(SqliteDataReader reader, string column)
    {
        int ordinal = reader.GetOrdinal(column);
        return reader.IsDBNull(ordinal) ? null : DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(ordinal));
    }

    private static string? GetString(SqliteDataReader reader, string column)
    {
        int ordinal = reader.GetOrdinal(column);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static string? Truncate(string? value, int max) => value is null || value.Length <= max ? value : value[..max];

    public void Dispose()
    {
        lock (sync)
        {
            connection.Dispose();
        }
    }
}
