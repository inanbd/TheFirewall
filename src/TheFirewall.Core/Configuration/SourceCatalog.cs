namespace TheFirewall.Core.Configuration;

/// <summary>Combines the built-in sources (with user overrides) and custom sources into the effective list.</summary>
public static class SourceCatalog
{
    public static List<LogSourceDefinition> GetEffective(FirewallSettings settings)
    {
        var result = new List<LogSourceDefinition>();
        foreach (var builtIn in BuiltInSources.All)
        {
            var copy = builtIn.Clone();
            copy.IsBuiltIn = true;
            if (settings.SourceOverrides.TryGetValue(builtIn.Id, out var ov))
            {
                if (ov.Enabled is bool enabled)
                {
                    copy.Enabled = enabled;
                }

                if (ov.FailedAttemptsBeforeBan > 0)
                {
                    copy.FailedAttemptsBeforeBan = ov.FailedAttemptsBeforeBan;
                }
            }

            result.Add(copy);
        }

        foreach (var custom in settings.CustomSources)
        {
            var copy = custom.Clone();
            copy.IsBuiltIn = false;
            result.Add(copy);
        }

        return result;
    }
}
