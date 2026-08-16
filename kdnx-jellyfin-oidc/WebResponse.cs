using System;
using System.IO;
using System.Reflection;

#nullable enable

namespace Kdnx.Jellyfin.Oidc;

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

    /// <summary>Substitutions are JSON-encoded, so they land in the script as literals.</summary>
    public static string Generator(string data, string provider, string pathBase, string nonce)
    {
        pathBase = pathBase.TrimEnd('/');

        string jsonPathBase = System.Text.Json.JsonSerializer.Serialize(pathBase);
        string jsonAuthUrl = System.Text.Json.JsonSerializer.Serialize($"{pathBase}/sso/OID/Auth/{provider}");
        string jsonData = System.Text.Json.JsonSerializer.Serialize(data);

        return _baseHtml.Value
            .Replace("\"___jsonPunycodeBaseUrl___\"", jsonPathBase)
            .Replace("\"___jsonData___\"", jsonData)
            .Replace("\"___jsonAuthUrl___\"", jsonAuthUrl)
            .Replace("___nonce___", nonce);
    }
}
