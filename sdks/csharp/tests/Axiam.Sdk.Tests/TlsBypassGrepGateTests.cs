using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// In-suite guard for SC#4 / T-21-21: the ONLY place
/// <c>ServerCertificateCustomValidationCallback</c> may be assigned anywhere in the
/// two published packages (<c>Axiam.Sdk</c>/<c>Axiam.Sdk.AspNetCore</c>) is the
/// additive <c>customCa</c> chain-trust-store callback in
/// <c>Rest/AxiamHttpClientFactory.cs</c> — never a bare <c>=&gt; true</c> or any other
/// validation-disabling assignment (CONTRACT.md &#167;6). Mirrors the CI grep gate
/// (plan 21-07, Task 3) as a fast, in-suite regression guard; modeled on the
/// Go/Java narrowed-gate precedent (STATE.md Phase 20-05) — the gate targets
/// concrete bypass idioms, not the legitimate <c>customCa</c> method/field names.
/// </summary>
/// <remarks>
/// Scans only the two PACKAGE project directories
/// (<c>sdks/csharp/Axiam.Sdk/</c>, <c>sdks/csharp/Axiam.Sdk.AspNetCore/</c>) —
/// the test tree and <c>examples/</c> are excluded by construction, since this
/// class never walks either directory. <c>obj/</c>/<c>bin/</c> build output is
/// also skipped explicitly.
/// </remarks>
[Trait("Category", "Fast")]
public sealed class TlsBypassGrepGateTests
{
    private const string BypassPattern = "ServerCertificateCustomValidationCallback";

    /// <summary>
    /// A line containing <see cref="BypassPattern"/> is only permitted when it ALSO
    /// contains one of these markers — the additive customCa chain-trust idiom
    /// (<c>chain.ChainPolicy.CustomTrustStore.Add(...)</c> /
    /// <c>X509ChainTrustMode.CustomRootTrust</c>), never a bare unconditional-true
    /// bypass.
    /// </summary>
    private static readonly string[] AllowedMarkers = { "CustomTrustStore", "CustomRootTrust" };

    [Fact]
    public void NoTlsBypass_Anywhere_InPackageSource_ExceptTheAdditiveCustomCaPattern()
    {
        string csharpRoot = FindCSharpRoot();

        string[] packageDirs =
        {
            Path.Combine(csharpRoot, "Axiam.Sdk"),
            Path.Combine(csharpRoot, "Axiam.Sdk.AspNetCore"),
        };

        var offendingLines = new List<string>();

        foreach (string dir in packageDirs)
        {
            Assert.True(Directory.Exists(dir), $"expected package directory to exist: {dir}");

            foreach (string file in Directory.EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories))
            {
                if (IsBuildOutput(file))
                {
                    continue;
                }

                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];
                    if (!line.Contains(BypassPattern, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    bool isAllowed = AllowedMarkers.Any(marker => line.Contains(marker, StringComparison.Ordinal));
                    if (!isAllowed)
                    {
                        offendingLines.Add($"{file}:{i + 1}: {line.Trim()}");
                    }
                }
            }
        }

        Assert.True(
            offendingLines.Count == 0,
            "TLS-bypass gate (SC#4) found disallowed ServerCertificateCustomValidationCallback " +
            "usage — only the additive customCa CustomTrustStore/CustomRootTrust pattern is " +
            "permitted anywhere in Axiam.Sdk/Axiam.Sdk.AspNetCore:\n" +
            string.Join('\n', offendingLines));
    }

    private static bool IsBuildOutput(string filePath)
    {
        string normalized = filePath.Replace('\\', '/');
        return normalized.Contains("/obj/", StringComparison.Ordinal) || normalized.Contains("/bin/", StringComparison.Ordinal);
    }

    /// <summary>Walks up from the test assembly's runtime location to find the
    /// directory containing <c>Axiam.Sdk.sln</c> (i.e. <c>sdks/csharp/</c>).</summary>
    private static string FindCSharpRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Axiam.Sdk.sln")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }

        throw new InvalidOperationException(
            "could not locate sdks/csharp (Axiam.Sdk.sln not found in any ancestor directory of the test assembly)");
    }
}
