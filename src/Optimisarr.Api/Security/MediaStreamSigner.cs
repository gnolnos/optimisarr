using System.Security.Cryptography;
using System.Text;

namespace Optimisarr.Api.Security;

/// <summary>
/// Short-lived, single-file capability URLs for native media players (iOS/Android AVPlayer, which
/// cannot attach an Authorization header). A signed URL grants read access to exactly the one
/// <c>/content</c> path it names, for a bounded window, and never carries the admin token. This is
/// purely additive: the web keeps authenticating media with its HttpOnly session cookie, and the
/// mobile app signs once (over its normal, genuinely authenticated fetch) and hands the bounded URL
/// to the native player.
/// </summary>
public static class MediaStreamSigner
{
    /// <summary>How long a signed URL stays valid. Plenty for a player to begin streaming; short
    /// enough that a leaked URL is a one-file, ten-minute capability, not a standing grant.</summary>
    public const int TtlSeconds = 10 * 60;

    private const string QueryExp = "exp";
    private const string QuerySig = "sig";

    public static string SignContentUrl(string relativePath, string adminToken)
    {
        var exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + TtlSeconds;
        var sig = Signature(relativePath, exp, adminToken);
        return $"{relativePath}?{QueryExp}={exp}&{QuerySig}={sig}";
    }

    /// <summary>Accepts signed URLs only for <c>/content</c> paths — the media a native player
    /// needs — never for admin-facing API. The signature is HMAC over (path, expiry) with a key
    /// derived from the admin token, so a valid signed URL cannot be forged and can only ever
    /// authorise the exact file it names.</summary>
    public static bool IsValidContentUrl(HttpRequest request, string adminToken)
    {
        var path = request.Path.Value;
        if (path is null || !path.EndsWith("/content", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!request.Query.TryGetValue(QueryExp, out var expRaw)
            || !long.TryParse(expRaw.ToString(), out var exp))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // Not yet valid, too old, or (clamped) absurdly far in the future.
        if (exp <= now || exp > now + 2 * TtlSeconds)
        {
            return false;
        }

        if (!request.Query.TryGetValue(QuerySig, out var sigRaw))
        {
            return false;
        }

        var suppliedHash = SHA256.HashData(Encoding.UTF8.GetBytes(sigRaw.ToString() ?? string.Empty));
        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(Signature(path, exp, adminToken)));
        return CryptographicOperations.FixedTimeEquals(suppliedHash, expectedHash);
    }

    /// <summary>The key is the admin token's own hash, so no new secret has to be configured or
    /// rotated; rotating the admin token invalidates outstanding signed URLs (which expire soon
    /// anyway).</summary>
    private static string Signature(string path, long exp, string adminToken)
    {
        var key = SHA256.HashData(Encoding.UTF8.GetBytes(adminToken ?? string.Empty));
        using var hmac = new HMACSHA256(key);
        var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{path}:{exp}"));
        return Convert.ToHexString(mac).ToLowerInvariant();
    }
}
