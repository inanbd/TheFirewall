using TheFirewall.App.Services;

namespace TheFirewall.App.ViewModels;

/// <summary>Shared services handed to every page.</summary>
public sealed class AppServices(IFirewallClient client, SettingsSession settings, AppPreferences preferences)
{
    public IFirewallClient Client { get; } = client;

    public SettingsSession Settings { get; } = settings;

    public AppPreferences Preferences { get; } = preferences;

    /// <summary>Navigates the main window to a page by key (set by the main view model).</summary>
    public Action<string>? Navigate { get; set; }

    /// <summary>Opens the details window for an address (set by the main window).</summary>
    public Action<string>? ShowAddressDetails { get; set; }
}
