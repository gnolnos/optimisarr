using System.Security.Cryptography;
using System.Text;

namespace Optimisarr.Api.Security;

/// <summary>
/// Short-lived, single-file capability URLs for a native media player. iOS AVPlayer and Android
/// ExoPlayer send no headers of their own, so the mobile app asks for a signed URL over its normal
/// authenticated fetch and hands the result straight to the player. A signed URL authorises exactly
/// the one <c>/content</c> path it names, only until it expires, and never carries the admin token:
/// the signature is an HMAC over that path and its expiry, keyed by the token itself, so only a
/// request the admin bearer would already allow can be signed at all.
/// </summary>
public static class MediaStreamSigner
{
    /// <summary>
    /// Long enough for a player to open the stream, short enough that a leaked URL is a one-file,
    /// quarter-hour capability rather than a standing grant.
    /// </summary>
    public const int TtlSeconds = 15 * 60;

    /// <summary>128 bits of the MAC: far beyond guessing, and short enough to read in a log.</summary>
    private const int SignatureHexLength = 32;

    private const string ExpiryQuery = "exp";
    private const string SignatureQuery = "sig";

    /// <summary>
    /// Only a media <c>/content</c> route can be signed, and only as a bare relative path: a query
    /// string, a fragment, an escape or a traversal segment is refused rather than signed, so a
    /// caller cannot widen what its URL covers.
    /// </summary>
    public static bool IsSignablePath(string? relativePath) =>
        relativePath is not null
        && relativePath.StartsWith("/api/", StringComparison.Ordinal)
        && relativePath.EndsWith("/content", StringComparison.Ordinal)
        && !relativePath.Contains("..", StringComparison.Ordinal)
        && relativePath.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '/' or '-' or '_' or '.');

    public static string SignedUrl(string relativePath, string adminToken) =>
        SignedUrl(relativePath, adminToken, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + TtlSeconds);

    public static string SignedUrl(string relativePath, string adminToken, long expiresAtUnixSeconds) =>
        $"{relativePath}?{ExpiryQuery}={expiresAtUnixSeconds}"
        + $"&{SignatureQuery}={Signature(relativePath, expiresAtUnixSeconds, adminToken)}";

    /// <summary>
    /// Whether this request carries a valid, unexpired signature for the exact path it is asking
    /// for. The path is part of the signed message, so a URL minted for one file cannot open
    /// another, and an expired one cannot be renewed without the admin token.
    /// </summary>
    public static bool IsSignedContentRequest(HttpRequest request, string adminToken)
    {
        var path = request.Path.Value;
        if (!IsSignablePath(path))
        {
            return false;
        }

        if (!long.TryParse(request.Query[ExpiryQuery].ToString(), out var expiresAt))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // Expired, or dated so far ahead that it cannot have come from this server.
        if (expiresAt <= now || expiresAt > now + 2 * TtlSeconds)
        {
            return false;
        }

        return FixedTimeEquals(
            request.Query[SignatureQuery].ToString(),
            Signature(path!, expiresAt, adminToken));
    }

    /// <summary>
    /// The key is the admin token's own hash, so there is no second secret to configure or rotate:
    /// rotating the admin token invalidates every outstanding signed URL, which expire anyway.
    /// </summary>
    private static string Signature(string relativePath, long expiresAtUnixSeconds, string adminToken)
    {
        var key = SHA256.HashData(Encoding.UTF8.GetBytes(adminToken));
        var mac = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes($"{relativePath}.{expiresAtUnixSeconds}"));
        return Convert.ToHexString(mac).ToLowerInvariant()[..SignatureHexLength];
    }

    private static bool FixedTimeEquals(string supplied, string expected) =>
        CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(supplied)),
            SHA256.HashData(Encoding.UTF8.GetBytes(expected)));
}
