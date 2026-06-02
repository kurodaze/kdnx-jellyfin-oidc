using System;
using System.IO;
using System.Reflection;

#nullable enable

namespace Kdnx.Jellyfin.Oidc;

/// <summary>
/// A helper class to return HTML for the client's auth flow.
/// </summary>
public static class WebResponse
{
    private static readonly Lazy<string> _baseHtml = new Lazy<string>(() =>
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("Kdnx.Jellyfin.Oidc.Views.callback.html");
        if (stream == null)
        {
            // Fallback in case the resource isn't found
            return "<html><body>Internal Error: Missing callback template.</body></html>";
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    });

    private static string GetHtmlTemplate() => _baseHtml.Value;

    /// <summary>
    /// A generator for the web response that incorporates the data from the server.
    /// </summary>
    /// <param name="data">The data of the auth flow (the state ID for OpenID).</param>
    /// <param name="provider">The name of the provider to callback to.</param>
    /// <param name="pathBase">The path base URL of the Jellyfin installation.</param>
    /// <param name="mode">The mode of the function; e.g. OID.</param>
    /// <param name="nonce">The nonce string to include in the OIDC state.</param>
    /// <returns>A string with the HTML to serve to the client.</returns>
    public static string Generator(string data, string provider, string pathBase, string mode, string nonce)
    {
        pathBase = pathBase.TrimEnd('/');

        string jsonPathBase = System.Text.Json.JsonSerializer.Serialize(pathBase);
        string jsonAuthUrl = System.Text.Json.JsonSerializer.Serialize($"{pathBase}/sso/{mode}/Auth/{provider}");
        string jsonData = System.Text.Json.JsonSerializer.Serialize(data);

        var template = GetHtmlTemplate();

        return template
            .Replace("\"___jsonPunycodeBaseUrl___\"", jsonPathBase)
            .Replace("\"___jsonData___\"", jsonData)
            .Replace("\"___jsonAuthUrl___\"", jsonAuthUrl)
            .Replace("___nonce___", nonce);
    }
}
