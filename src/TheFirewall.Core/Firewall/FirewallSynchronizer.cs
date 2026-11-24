using Microsoft.Extensions.Logging;
using TheFirewall.Core.Data;

namespace TheFirewall.Core.Firewall;

public sealed class FirewallSyncResult
{
    public int Updated { get; set; }

    public int Unchanged { get; set; }

    public int Deleted { get; set; }

    public List<string> Errors { get; } = [];
}

/// <summary>Brings the firewall in line with a plan, touching only rules whose fingerprint changed.</summary>
public sealed class FirewallSynchronizer(IFirewallBackend backend, FirewallDatabase db, ILogger logger)
{
    private Dictionary<string, string>? hashes;

    public IFirewallBackend Backend => backend;

    public FirewallSyncResult Apply(FirewallPlan plan, string prefix)
    {
        hashes ??= db.GetRuleHashes();
        var result = new FirewallSyncResult();
        var existing = new HashSet<string>(backend.GetRuleNames(prefix), StringComparer.OrdinalIgnoreCase);
        var newHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in plan.Rules)
        {
            wanted.Add(rule.Name);
            var hash = rule.ComputeHash();
            if (existing.Contains(rule.Name) && hashes.TryGetValue(rule.Name, out var previous) && previous == hash)
            {
                newHashes[rule.Name] = hash;
                result.Unchanged++;
                continue;
            }

            try
            {
                backend.SetRule(rule);
                newHashes[rule.Name] = hash;
                result.Updated++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unable to write firewall rule {Rule}", rule.Name);
                result.Errors.Add($"{rule.Name}: {ex.Message}");
            }
        }

        foreach (var name in existing.Where(n => !wanted.Contains(n)))
        {
            try
            {
                backend.DeleteRule(name);
                result.Deleted++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unable to delete firewall rule {Rule}", name);
                result.Errors.Add($"{name}: {ex.Message}");
            }
        }

        if (result.Updated > 0 || result.Deleted > 0 || newHashes.Count != hashes.Count)
        {
            hashes = newHashes;
            db.ReplaceRuleHashes(newHashes);
        }

        if (result.Updated > 0 || result.Deleted > 0)
        {
            logger.LogInformation("Firewall synchronised: {Updated} rules written, {Deleted} removed, {Unchanged} unchanged",
                result.Updated, result.Deleted, result.Unchanged);
        }

        return result;
    }

    /// <summary>Deletes every rule that starts with the prefix.</summary>
    public int RemoveAll(string prefix)
    {
        int removed = 0;
        foreach (var name in backend.GetRuleNames(prefix))
        {
            try
            {
                backend.DeleteRule(name);
                removed++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Unable to delete firewall rule {Rule}", name);
            }
        }

        hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        db.ReplaceRuleHashes(hashes);
        return removed;
    }
}
