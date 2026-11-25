using Optimisarr.Api.Endpoints;
using Optimisarr.Api.Security;

namespace Optimisarr.Api;

public static class StreamSignEndpoints
{
    /// <summary>
    /// Hands a native player a short-lived signed URL to a media <c>/content</c> path. The caller
    /// must already be authenticated (this is an /api route, so Bearer or the session cookie is
    /// required by the auth middleware); the returned URL is the only thing the player needs, and
    /// it expires in minutes and covers exactly that one file.
    /// </summary>
    public static IEndpointRouteBuilder MapStreamSigningEndpoints(this IEndpointRouteBuilder app, string? adminToken)
    {
        app.MapGet("/api/stream/sign", (HttpContext context) =>
        {
            var relative = context.Request.Query["path"].ToString();
            if (string.IsNullOrWhiteSpace(relative)
                || !relative.StartsWith("/api/", StringComparison.OrdinalIgnoreCase)
                || !relative.EndsWith("/content", StringComparison.OrdinalIgnoreCase))
            {
                return Results.BadRequest(new ApiError(
                    "stream.sign.pathInvalid",
                    "Only /api/*/content media paths can be signed."));
            }

            return Results.Ok(new { url = MediaStreamSigner.SignContentUrl(relative, adminToken ?? string.Empty) });
        }).WithName("SignStreamContent");

        return app;
    }
}
