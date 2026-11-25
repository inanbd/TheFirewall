using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using TheFirewall.App.ViewModels;
using TheFirewall.App.Views;

namespace TheFirewall.App;

/// <summary>
/// "--screenshots &lt;folder&gt;" renders every page (with demo data) to PNG files and exits.
/// Used by CI to catch XAML errors at runtime and to produce documentation images.
/// </summary>
internal static class ScreenshotRunner
{
    public static bool IsRunning { get; set; }

    public static async Task RunAsync(App app, MainViewModel viewModel, string outputDirectory)
    {
        IsRunning = true;
        int exitCode = 0;
        try
        {
            Directory.CreateDirectory(outputDirectory);
            var window = new MainWindow(viewModel, new Services.AppPreferences())
            {
                Width = 1280,
                Height = 840,
                WindowStartupLocation = WindowStartupLocation.Manual,
                Left = 0,
                Top = 0,
                ShowActivated = false,
            };
            app.MainWindow = window;
            window.Show();

            int index = 1;
            foreach (var page in viewModel.Pages.Concat(viewModel.FooterPages).ToList())
            {
                viewModel.Navigate(page.Key);
                await SettleAsync();
                Save(window, Path.Combine(outputDirectory, $"{index++:00}-{page.Key}.png"));
            }

            App.ApplyTheme("Dark");
            viewModel.Navigate("dashboard");
            await SettleAsync();
            Save(window, Path.Combine(outputDirectory, $"{index++:00}-dashboard-dark.png"));
            viewModel.Navigate("activity");
            if (viewModel.Pages.OfType<ActivityViewModel>().FirstOrDefault() is { Items.Count: > 2 } activity)
            {
                // A selected row shows the "block this country" button in its Country cell.
                activity.Selected = activity.Items[2];
            }

            await SettleAsync();
            Save(window, Path.Combine(outputDirectory, $"{index++:00}-activity-dark.png"));
            App.ApplyTheme("Light");

            // Dialogs
            var services = new AppServices(new Services.DemoClient(app.Dispatcher, live: false), new Services.SettingsSession(new Services.DemoClient(app.Dispatcher, live: false)), new Services.AppPreferences());
            foreach (var (name, dialog) in new (string, Window)[]
            {
                ("dialog-rule", new Views.Dialogs.RuleEditorWindow(new Core.Configuration.CustomFirewallRule
                {
                    Name = "Remote Desktop from office only",
                    Action = Core.Configuration.RuleAction.Allow,
                    Protocol = Core.Configuration.RuleProtocol.Tcp,
                    LocalPorts = "3389",
                    RemoteAddresses = "203.0.113.0/24",
                }, isNew: false)),
                ("dialog-source", new Views.Dialogs.SourceEditorWindow(services.Client, Core.Configuration.BuiltInSources.Find("custom-logfile")!.Clone(), isBuiltIn: false, isNew: true)),
                ("dialog-ban", new Views.Dialogs.BanDialog()),
                ("dialog-address", new Views.Dialogs.AddressDialog(whitelist: true)),
                ("dialog-details", new Views.Dialogs.AddressDetailsWindow(services, "45.141.84.10")),
            })
            {
                dialog.ShowActivated = false;
                dialog.WindowStartupLocation = WindowStartupLocation.Manual;
                dialog.Left = 0;
                dialog.Top = 0;
                dialog.Show();
                await SettleAsync();
                Save(dialog, Path.Combine(outputDirectory, $"{index++:00}-{name}.png"));
                dialog.Close();
            }

            window.CloseForExit();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            exitCode = 2;
        }

        app.Shutdown(exitCode);
    }

    private static async Task SettleAsync()
    {
        for (int i = 0; i < 6; i++)
        {
            await Task.Delay(250);
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
        }
    }

    private static void Save(Window window, string path)
    {
        // The window's template root covers the whole client area, including the content's margins.
        var content = VisualTreeHelper.GetChildrenCount(window) > 0 && VisualTreeHelper.GetChild(window, 0) is FrameworkElement root
            ? root
            : window.Content as FrameworkElement;
        if (content is null || content.ActualWidth < 1 || content.ActualHeight < 1)
        {
            return;
        }

        var dpi = VisualTreeHelper.GetDpi(window);
        var rect = new Rect(0, 0, content.ActualWidth, content.ActualHeight);
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            var background = Application.Current.TryFindResource("SolidBackgroundFillColorBaseBrush") as Brush ?? Brushes.White;
            dc.DrawRectangle(background, null, rect);
            dc.DrawRectangle(new VisualBrush(content) { Stretch = Stretch.None, AlignmentX = AlignmentX.Left, AlignmentY = AlignmentY.Top }, null, rect);
        }

        var bitmap = new RenderTargetBitmap((int)Math.Ceiling(rect.Width * dpi.DpiScaleX), (int)Math.Ceiling(rect.Height * dpi.DpiScaleY),
            dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(path);
        encoder.Save(file);
    }
}
