using System.Diagnostics;
using System.Reflection;
using CommunityToolkit.Mvvm.Input;

namespace TheFirewall.App.ViewModels;

public sealed partial class AboutViewModel(AppServices services) : PageViewModel(services)
{
    public const string ProjectUrl = "https://github.com/inanbd/TheFirewall";

    public override string Key => "about";

    public override string Title => "About";

    public override string Glyph => "";

    public string AppVersion { get; } =
        typeof(AboutViewModel).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "1.0.0";

    public string ServiceVersion => Client.ServiceVersion ?? "not connected";

    public string RuntimeVersion => Environment.Version.ToString();

    protected override Task LoadAsync()
    {
        OnPropertyChanged(nameof(ServiceVersion));
        return Task.CompletedTask;
    }

    [RelayCommand]
    private void OpenLink(string? url)
    {
        if (!string.IsNullOrWhiteSpace(url) && url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
    }
}
