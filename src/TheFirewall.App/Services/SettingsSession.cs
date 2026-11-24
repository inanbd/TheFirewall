using TheFirewall.Core.Configuration;

namespace TheFirewall.App.Services;

/// <summary>
/// Shared copy of the service settings for the pages that edit them. Changes are applied through
/// <see cref="SaveAsync(Action{FirewallSettings})"/>, which sends the whole settings object to the service.
/// </summary>
public sealed class SettingsSession(IFirewallClient client)
{
    private FirewallSettings? current;

    public event EventHandler? Changed;

    public FirewallSettings? Current => current;

    public async Task<FirewallSettings> LoadAsync(bool force = false)
    {
        if (current is null || force)
        {
            current = await client.GetSettingsAsync();
            Changed?.Invoke(this, EventArgs.Empty);
        }

        return current;
    }

    /// <summary>Applies a change and saves. Shows errors to the user and returns false when the save failed.</summary>
    public async Task<bool> SaveAsync(Action<FirewallSettings> change)
    {
        try
        {
            var baseline = await LoadAsync();
            var copy = SettingsStore.Clone(baseline);
            change(copy);
            var result = await client.SaveSettingsAsync(copy);
            if (!result.Saved)
            {
                UiDialogs.ShowValidationErrors(result.Errors);
                return false;
            }

            current = await client.GetSettingsAsync();
            Changed?.Invoke(this, EventArgs.Empty);
            return true;
        }
        catch (Exception ex)
        {
            UiDialogs.HandleError(ex, "Unable to save settings");
            return false;
        }
    }

    public void Invalidate() => current = null;
}
