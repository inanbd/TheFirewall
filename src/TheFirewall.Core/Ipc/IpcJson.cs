using System.Text.Json;
using System.Text.Json.Serialization;

namespace TheFirewall.Core.Ipc;

public static class IpcJson
{
    /// <summary>Options used on the wire between the service and the app.</summary>
    public static readonly JsonSerializerOptions Options = Create(indented: false);

    /// <summary>Options used for the settings file and exports (indented, human editable).</summary>
    public static readonly JsonSerializerOptions SettingsOptions = Create(indented: true);

    private static JsonSerializerOptions Create(bool indented)
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = indented,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };
        options.Converters.Add(new JsonStringEnumConverter());
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
}

/// <summary>One line of the newline-delimited JSON protocol.</summary>
public sealed class IpcMessage
{
    /// <summary>Request id; responses echo it. 0 for server-pushed events.</summary>
    public long Id { get; set; }

    /// <summary>Command name for requests, "response" for replies, or the event name for pushes.</summary>
    public string Type { get; set; } = string.Empty;

    public JsonElement? Payload { get; set; }

    public bool Ok { get; set; } = true;

    public string? Error { get; set; }

    /// <summary>Machine readable error code, e.g. <see cref="IpcErrorCodes.ElevationRequired"/>.</summary>
    public string? ErrorCode { get; set; }
}

public static class IpcErrorCodes
{
    public const string ElevationRequired = "elevation_required";
    public const string Invalid = "invalid";
    public const string NotFound = "not_found";
    public const string Internal = "internal";
}

/// <summary>Error that is reported to the client with a friendly message.</summary>
public sealed class IpcException(string message, string code = IpcErrorCodes.Invalid) : Exception(message)
{
    public string Code { get; } = code;
}

public static class IpcCommands
{
    public const string PipeName = "TheFirewall.Service.v1";

    public const string Hello = "hello";
    public const string Subscribe = "subscribe";
    public const string Status = "status";
    public const string Stats = "stats";
    public const string Activity = "activity.query";
    public const string Bans = "bans.list";
    public const string Watched = "watched.list";
    public const string Ban = "ban";
    public const string Unban = "unban";
    public const string ClearBans = "bans.clear";
    public const string ImportBans = "bans.import";
    public const string Lookup = "lookup";
    public const string GetSettings = "settings.get";
    public const string SaveSettings = "settings.save";
    public const string SetProtection = "protection.set";
    public const string Sources = "sources.list";
    public const string TestSource = "sources.test";
    public const string Countries = "countries.list";
    public const string UpdateGeo = "geo.update";
    public const string Feeds = "feeds.list";
    public const string RefreshFeeds = "feeds.refresh";
    public const string SyncFirewall = "firewall.sync";

    /// <summary>Server push: a new <see cref="Data.ActivityEntry"/>.</summary>
    public const string EventActivity = "event.activity";

    /// <summary>Server push: an existing <see cref="Data.ActivityEntry"/> changed (same id).</summary>
    public const string EventActivityUpdated = "event.activity.updated";

    /// <summary>Server push: <see cref="ActivityRemovedEvent"/>.</summary>
    public const string EventActivityRemoved = "event.activity.removed";

    /// <summary>Server push: a new <see cref="ServiceStatusDto"/>.</summary>
    public const string EventStatus = "event.status";

    /// <summary>Commands that change state and therefore need an elevated (administrator) client.</summary>
    public static readonly IReadOnlySet<string> AdminCommands = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Ban, Unban, ClearBans, ImportBans, SaveSettings, SetProtection, UpdateGeo, RefreshFeeds, SyncFirewall,
    };
}
