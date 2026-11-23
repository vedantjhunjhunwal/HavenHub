using HavenHub.Api;

await using var app = HavenHubApp.Create(args);
await app.RunAsync();
