using Optimisarr.Api.Security;

namespace Optimisarr.Api.Endpoints;

internal static class StreamSignEndpoints
{
    public static void MapStreamSignEndpoints(this WebApplication app, string? adminToken)
    {
        // A native media player (AVPlayer, ExoPlayer) sends no headers, so the mobile app asks here
        // — over its own authenticated fetch — for a signed URL to the content path it is about to
        // play, then hands that URL to the player unchanged. The reply stays relative: the client
        // prefixes its own base address.
        app.MapGet("/api/stream/sign", (string? path) =>
        {
            if (!MediaStreamSigner.IsSignablePath(path))
            {
                return ApiErrors.BadRequest(
                    "stream.sign.pathInvalid",
                    "Only a relative /api/…/content media path can be signed.",
                    new { path });
            }

            // With no admin token configured nothing is authenticated, so the plain path already
            // plays; signing it would only imply a protection that is not there.
            return Results.Ok(new SignedStreamUrl(AdminTokenAuth.Required(adminToken)
                ? MediaStreamSigner.SignedUrl(path!, adminToken!)
                : path!));
        })
        .WithName("SignStreamUrl")
        .Produces<SignedStreamUrl>()
        .Produces<ApiError>(StatusCodes.Status400BadRequest);
    }
}

/// <summary>A relative content URL a native player can open without sending any header.</summary>
internal sealed record SignedStreamUrl(string Url);
