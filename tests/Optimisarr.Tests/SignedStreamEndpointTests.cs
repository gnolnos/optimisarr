using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Optimisarr.Api.Security;
using Optimisarr.Core.Domain;
using Optimisarr.Data;

namespace Optimisarr.Tests;

/// <summary>
/// What the mobile app needs from the server: one job by its id, shaped exactly like the row the
/// queue feed builds, and a short-lived signed URL a native player can open with no header at all.
/// A signed URL is bound to its own path and its own expiry, so it opens that one file until it
/// expires and nothing else ever.
/// </summary>
[Collection(TokenedApiCollection.Name)]
public sealed class SignedStreamEndpointTests(AdminTokenAuthEndpointTests.TokenedApi api)
{
    [Fact]
    public async Task One_job_by_id_is_shaped_exactly_like_its_row_in_the_queue_feed()
    {
        var (jobId, mediaId) = await SeedAsync([1, 2, 3]);
        using var client = Admin();
        try
        {
            var single = await client.GetFromJsonElementAsync($"/api/jobs/{jobId}");
            var listed = (await client.GetFromJsonElementAsync("/api/jobs"))
                .EnumerateArray().Single(job => job.GetProperty("id").GetInt32() == jobId);

            Assert.Equal(jobId, single.GetProperty("id").GetInt32());
            Assert.Equal(nameof(JobStatus.ReadyToReplace), single.GetProperty("status").GetString());
            Assert.Equal(
                listed.EnumerateObject().Select(property => property.Name).Order(),
                single.EnumerateObject().Select(property => property.Name).Order());
            Assert.Equal(listed.GetRawText(), single.GetRawText());
        }
        finally { await CleanUpAsync(mediaId); }
    }

    [Fact]
    public async Task An_unknown_job_is_not_found()
    {
        using var client = Admin();

        using var response = await client.GetAsync("/api/jobs/2147483647");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains("job.notFound", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_signed_url_plays_the_content_it_names_without_any_header()
    {
        var bytes = new byte[] { 7, 7, 1, 2 };
        var (jobId, mediaId) = await SeedAsync(bytes);
        var path = $"/api/jobs/{jobId}/output/content";
        using var admin = Admin();
        try
        {
            var signed = (await admin.GetFromJsonElementAsync($"/api/stream/sign?path={path}"))
                .GetProperty("url").GetString()!;

            using var player = api.CreateClient();
            using var played = await player.GetAsync(signed);
            using var unsigned = await player.GetAsync(path);

            Assert.StartsWith(path + "?exp=", signed);
            Assert.DoesNotContain(AdminTokenAuthEndpointTests.TokenedApi.Token, signed);
            Assert.Equal(HttpStatusCode.OK, played.StatusCode);
            Assert.Equal(bytes, await played.Content.ReadAsByteArrayAsync());
            // The signature is the only thing that opened it: the bare path is still closed.
            Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
        }
        finally { await CleanUpAsync(mediaId); }
    }

    [Fact]
    public async Task An_expired_signature_is_refused()
    {
        var (jobId, mediaId) = await SeedAsync([3]);
        try
        {
            var expired = MediaStreamSigner.SignedUrl(
                $"/api/jobs/{jobId}/output/content",
                AdminTokenAuthEndpointTests.TokenedApi.Token,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 1);

            using var player = api.CreateClient();
            using var response = await player.GetAsync(expired);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        finally { await CleanUpAsync(mediaId); }
    }

    [Fact]
    public async Task A_signature_minted_for_one_file_does_not_open_another()
    {
        var (firstJob, firstMedia) = await SeedAsync([1]);
        var (secondJob, secondMedia) = await SeedAsync([2]);
        using var admin = Admin();
        try
        {
            var signed = (await admin.GetFromJsonElementAsync(
                $"/api/stream/sign?path=/api/jobs/{firstJob}/output/content"))
                .GetProperty("url").GetString()!;
            var query = signed[signed.IndexOf('?')..];

            using var player = api.CreateClient();
            using var elsewhere = await player.GetAsync($"/api/jobs/{secondJob}/output/content{query}");
            using var named = await player.GetAsync(signed);

            Assert.Equal(HttpStatusCode.Unauthorized, elsewhere.StatusCode);
            Assert.Equal(HttpStatusCode.OK, named.StatusCode);
        }
        finally
        {
            await CleanUpAsync(firstMedia);
            await CleanUpAsync(secondMedia);
        }
    }

    [Theory]
    [InlineData("/api/settings")]
    [InlineData("/api/jobs/1/log")]
    [InlineData("https://elsewhere.example/api/media/1/content")]
    [InlineData("/api/media/../settings/content")]
    [InlineData("")]
    public async Task Only_a_relative_media_content_path_can_be_signed(string path)
    {
        using var client = Admin();

        using var response = await client.GetAsync($"/api/stream/sign?path={Uri.EscapeDataString(path)}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("stream.sign.pathInvalid", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Signing_itself_needs_the_admin_token()
    {
        using var client = api.CreateClient();

        using var response = await client.GetAsync("/api/stream/sign?path=/api/media/1/content");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private HttpClient Admin()
    {
        var client = api.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", AdminTokenAuthEndpointTests.TokenedApi.Token);
        return client;
    }

    private async Task<(int JobId, int MediaId)> SeedAsync(byte[] output)
    {
        var root = Path.Combine(api.LibraryDirectory, "signed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var source = Path.Combine(root, "tape.mkv");
        await File.WriteAllBytesAsync(source, new byte[32]);
        var outputPath = Path.Combine(root, "tape.optimised.mkv");
        await File.WriteAllBytesAsync(outputPath, output);
        using var scope = api.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OptimisarrDbContext>();
        var library = new Library { Name = "Signed " + Guid.NewGuid().ToString("N"), Path = root, AutoEnqueueEnabled = false };
        db.Libraries.Add(library);
        await db.SaveChangesAsync();
        var file = new MediaFile
        {
            LibraryId = library.Id, Path = source, RelativePath = "tape.mkv", SizeBytes = 32,
            ModifiedAt = DateTimeOffset.UtcNow, Status = MediaFileStatus.Probed, MediaKind = MediaKind.Video,
        };
        db.MediaFiles.Add(file);
        await db.SaveChangesAsync();
        var job = new Job
        {
            MediaFileId = file.Id, LibraryId = library.Id, Status = JobStatus.ReadyToReplace,
            Type = JobType.Normal, WorkOutputPath = outputPath, VerificationPassed = true,
        };
        db.Jobs.Add(job);
        await db.SaveChangesAsync();
        return (job.Id, file.Id);
    }

    private async Task CleanUpAsync(int mediaId)
    {
        // The fixture's database is shared: leave no job another test could try to replace.
        using var scope = api.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OptimisarrDbContext>();
        await db.Jobs.Where(job => job.MediaFileId == mediaId).ExecuteDeleteAsync();
        var file = await db.MediaFiles.AsNoTracking().SingleAsync(candidate => candidate.Id == mediaId);
        await db.MediaFiles.Where(candidate => candidate.Id == mediaId).ExecuteDeleteAsync();
        await db.Libraries.Where(library => library.Id == file.LibraryId).ExecuteDeleteAsync();
        Directory.Delete(Path.GetDirectoryName(file.Path)!, recursive: true);
    }
}

internal static class JsonElementHttpClientExtensions
{
    /// <summary>Reads a response as a JSON document, so a test can compare whole shapes.</summary>
    public static async Task<JsonElement> GetFromJsonElementAsync(this HttpClient client, string requestUri) =>
        JsonDocument.Parse(await client.GetStringAsync(requestUri)).RootElement;
}
