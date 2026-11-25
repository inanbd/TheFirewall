using TheFirewall.App.ViewModels;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Geo;

namespace TheFirewall.App.Services;

/// <summary>Blocks whole countries from the activity, ban and address pages (asks first, then saves the settings).</summary>
public static class CountryBlocker
{
    public static async Task<bool> BlockAsync(AppServices services, IEnumerable<string?> countryCodes)
    {
        var requested = countryCodes.ToList();
        if (!requested.Any(Countries.IsValidCode))
        {
            UiDialogs.Info("Country not known",
                "TheFirewall doesn't know which country this address is in, so there is no country to block.\n\n" +
                "Countries are looked up in the country database, which the service downloads automatically when it has internet access.");
            return false;
        }

        if (!services.Client.CanMakeChanges)
        {
            UiDialogs.RequestElevation();
            return false;
        }

        CountryBlockingSettings current;
        try
        {
            current = (await services.Settings.LoadAsync(force: true)).CountryBlocking;
        }
        catch (Exception ex)
        {
            UiDialogs.HandleError(ex, "Unable to block the country");
            return false;
        }

        var plan = CountryBlockChange.Plan(current, requested);
        var names = NameList(plan.Codes);
        bool plural = plan.Codes.Count > 1;
        switch (plan.Outcome)
        {
            case CountryBlockOutcome.AlreadyBlocked:
                UiDialogs.Info("Already blocked", current.Mode == CountryBlockingMode.AllowOnlySelected
                    ? $"{names} {(plural ? "are" : "is")} already blocked, because TheFirewall only allows connections from {NameList(current.Countries)}."
                    : $"{names} {(plural ? "are" : "is")} already blocked. You can see every blocked country on the Countries page.");
                return false;

            case CountryBlockOutcome.WouldBlockEverything:
                UiDialogs.Error("This is the last allowed country",
                    $"TheFirewall only allows connections from {names}. Blocking {(plural ? "them" : "it")} as well would block every address outside your local network.\n\n" +
                    "To change which countries may connect, use the Countries page.");
                return false;

            case CountryBlockOutcome.UnknownCountry:
                return false;
        }

        var where = string.IsNullOrWhiteSpace(current.Ports) ? "on every port" : $"on port(s) {current.Ports}";
        var question = current.Mode == CountryBlockingMode.AllowOnlySelected
            ? $"Remove {names} from the countries that may connect? Every address there will be blocked {where}."
            : $"Block every address from {names} {where}? This also blocks addresses there that have never tried to sign in.";
        var message = question + "\n\n" +
                      "Addresses on your whitelist and your local network are never blocked. Make sure you don't connect to this computer from " +
                      $"{(plural ? "these countries" : "this country")} yourself.\n\nYou can undo this on the Countries page.";
        if (!UiDialogs.Confirm(plural ? "Block countries" : $"Block {names}", message))
        {
            return false;
        }

        return await services.Settings.SaveAsync(s =>
        {
            s.CountryBlocking.Mode = plan.Mode;
            s.CountryBlocking.Countries = [.. plan.Countries];
        });
    }

    private static string NameList(IEnumerable<string> codes)
    {
        var names = codes.Select(Countries.GetName).ToList();
        return names.Count switch
        {
            0 => "no country",
            1 => names[0],
            <= 5 => string.Join(", ", names[..^1]) + " and " + names[^1],
            _ => string.Join(", ", names.Take(5)) + $" and {names.Count - 5} more",
        };
    }
}
