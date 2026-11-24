using CommunityToolkit.Mvvm.ComponentModel;
using TheFirewall.App.Services;

namespace TheFirewall.App.ViewModels;

public abstract partial class PageViewModel(AppServices services) : ObservableObject
{
    protected AppServices Services { get; } = services;

    protected IFirewallClient Client => Services.Client;

    public abstract string Key { get; }

    public abstract string Title { get; }

    public abstract string Glyph { get; }

    public virtual string? Subtitle => null;

    [ObservableProperty]
    public partial bool IsLoading { get; set; }

    [ObservableProperty]
    public partial string? LoadError { get; set; }

    /// <summary>True when the service accepts changes from this app.</summary>
    public bool CanEdit => Client.CanMakeChanges;

    public bool IsActive { get; private set; }

    public async Task NavigatedToAsync()
    {
        IsActive = true;
        OnPropertyChanged(nameof(CanEdit));
        await RefreshAsync();
    }

    public void NavigatedFrom()
    {
        IsActive = false;
        OnNavigatedFrom();
    }

    protected virtual void OnNavigatedFrom()
    {
    }

    /// <summary>Loads the page's data; errors are shown inline instead of in a dialog.</summary>
    public async Task RefreshAsync()
    {
        if (!Client.IsConnected)
        {
            LoadError = "TheFirewall service is not running, so there is nothing to show yet.";
            return;
        }

        IsLoading = true;
        try
        {
            await LoadAsync();
            LoadError = null;
        }
        catch (Exception ex)
        {
            LoadError = ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    protected abstract Task LoadAsync();

    /// <summary>Runs a change against the service with friendly error handling.</summary>
    protected async Task<bool> RunAsync(Func<Task> action, string failureTitle)
    {
        if (!Client.CanMakeChanges)
        {
            UiDialogs.RequestElevation();
            return false;
        }

        try
        {
            await action();
            return true;
        }
        catch (Exception ex)
        {
            UiDialogs.HandleError(ex, failureTitle);
            return false;
        }
    }
}
