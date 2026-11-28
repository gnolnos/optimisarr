using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Optimisarr.Tests;

/// <summary>
/// The host-load card the mobile Workers screen shows above the worker list: a live CPU/GPU
/// reading for the machine that is running the server itself. Unlike a worker's reading this is
/// sampled continuously by HostMetricsService and never depends on an encode being in flight, so
/// the shape is stable and cross-platform (CPU/GPU are null when this host reports none — e.g. a
/// non-Linux test runner — rather than a fabricated number).
/// </summary>
[Collection(TokenedApiCollection.Name)]
public sealed class SystemMetricsEndpointTests(AdminTokenAuthEndpointTests.TokenedApi api)
{
    [Fact]
    public async Task Host_metrics_reports_machine_identity_and_a_plausible_load_shape()
    {
        using var client = Admin();

        using var response = await client.GetAsync("/api/system/metrics");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("hostName").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("operatingSystem").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("architecture").GetString()));
        Assert.True(body.GetProperty("gpuSupported").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.True(
            body.GetProperty("cpuPercent").ValueKind is JsonValueKind.Number or JsonValueKind.Null,
            "cpuPercent must be a number or null, never a fabricated idle.");
        Assert.True(
            body.GetProperty("gpuPercent").ValueKind is JsonValueKind.Number or JsonValueKind.Null);
    }

    [Fact]
    public async Task Host_metrics_requires_the_admin_token()
    {
        using var client = api.CreateClient();

        using var response = await client.GetAsync("/api/system/metrics");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private HttpClient Admin()
    {
        var client = api.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", AdminTokenAuthEndpointTests.TokenedApi.Token);
        return client;
    }
}
