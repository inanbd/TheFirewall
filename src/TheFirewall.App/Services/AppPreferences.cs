using System.IO;
using System.Text.Json;

namespace TheFirewall.App.Services;

/// <summary>Per-user app preferences (not shared with the service).</summary>
public sealed class AppPreferences
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TheFirewall", "app-preferences.json");

    /// <summary>"System", "Light" or "Dark".</summary>
    public string Theme { get; set; } = "System";

    public bool HasShownTrayHint { get; set; }

    public double WindowWidth { get; set; } = 1180;

    public double WindowHeight { get; set; } = 780;

    public static AppPreferences Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                return JsonSerializer.Deserialize<AppPreferences>(File.ReadAllText(FilePath)) ?? new AppPreferences();
            }
        }
        catch (Exception)
        {
        }

        return new AppPreferences();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception)
        {
        }
    }
}
