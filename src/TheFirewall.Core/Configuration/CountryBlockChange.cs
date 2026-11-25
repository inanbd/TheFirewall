using TheFirewall.Core.Geo;

namespace TheFirewall.Core.Configuration;

public enum CountryBlockOutcome
{
    /// <summary>The settings change in the plan blocks the countries in <see cref="CountryBlockPlan.Codes"/>.</summary>
    Block,

    /// <summary>Every requested country is blocked already.</summary>
    AlreadyBlocked,

    /// <summary>In "allow only" mode the request would remove the last allowed country, which blocks everyone.</summary>
    WouldBlockEverything,

    /// <summary>None of the requested codes is a known country.</summary>
    UnknownCountry,
}

/// <param name="Outcome">What the request amounts to.</param>
/// <param name="Codes">The countries the change affects (for <see cref="CountryBlockOutcome.Block"/>), or the requested ones.</param>
/// <param name="Mode">The country blocking mode after the change.</param>
/// <param name="Countries">The country list after the change.</param>
public sealed record CountryBlockPlan(CountryBlockOutcome Outcome, IReadOnlyList<string> Codes, CountryBlockingMode Mode, IReadOnlyList<string> Countries);

/// <summary>Works out the settings change that blocks whole countries, whatever country blocking mode is in use.</summary>
public static class CountryBlockChange
{
    public static CountryBlockPlan Plan(CountryBlockingSettings settings, IEnumerable<string?> requested)
    {
        var codes = requested.Where(Countries.IsValidCode).Select(c => c!.ToUpperInvariant()).Distinct().ToList();
        var current = settings.Countries.Where(c => !string.IsNullOrWhiteSpace(c)).Select(c => c.Trim().ToUpperInvariant()).Distinct().ToList();
        if (codes.Count == 0)
        {
            return new(CountryBlockOutcome.UnknownCountry, codes, settings.Mode, current);
        }

        switch (settings.Mode)
        {
            case CountryBlockingMode.AllowOnlySelected:
            {
                // Only the listed countries may connect: blocking one means taking it off the list.
                var allowed = codes.Where(current.Contains).ToList();
                if (allowed.Count == 0)
                {
                    return new(CountryBlockOutcome.AlreadyBlocked, codes, settings.Mode, current);
                }

                var remaining = current.Except(allowed).ToList();
                return remaining.Count == 0
                    ? new(CountryBlockOutcome.WouldBlockEverything, allowed, settings.Mode, current)
                    : new(CountryBlockOutcome.Block, allowed, settings.Mode, remaining);
            }

            case CountryBlockingMode.BlockSelected:
            {
                var added = codes.Where(c => !current.Contains(c)).ToList();
                return added.Count == 0
                    ? new(CountryBlockOutcome.AlreadyBlocked, codes, settings.Mode, current)
                    : new(CountryBlockOutcome.Block, added, settings.Mode, [.. current, .. added]);
            }

            default:
                // Blocking was off. Countries ticked earlier stay unblocked: only the requested ones are blocked.
                return new(CountryBlockOutcome.Block, codes, CountryBlockingMode.BlockSelected, codes);
        }
    }
}
