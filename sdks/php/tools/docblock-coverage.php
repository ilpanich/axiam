<?php

declare(strict_types=1);

/**
 * Docblock-coverage gate for the hand-written public API.
 *
 * PHP has no de-facto "missing docblock" checker the way Rust has `missing_docs`,
 * Java has doclint, C# has CS1591 and Python has interrogate — phpstan checks the
 * CONTENT of a docblock but never that one EXISTS. Without this gate, the PHP SDK's
 * published API reference silently rots as new public methods land undocumented
 * (exactly how AuthzError::getAction/getResourceId shipped bare).
 *
 * Fails when any public class/interface/method under src/ lacks a preceding
 * docblock. src/Grpc/Gen is skipped: it is protoc output, not hand-written, and is
 * excluded from the published docs (phpdoc.dist.xml) and from phpstan for the same
 * reason.
 *
 * Usage: php tools/docblock-coverage.php   (exit 0 = fully documented)
 */

$root = dirname(__DIR__) . '/src';
$missing = [];
$total = 0;

$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
$paths = [];
foreach ($files as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $paths[] = $file->getPathname();
    }
}
sort($paths);

foreach ($paths as $path) {
    $relative = substr($path, strlen($root) + 1);

    // Generated protobuf stubs — not hand-written, not published.
    if (str_starts_with($relative, 'Grpc/Gen')) {
        continue;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        continue;
    }

    foreach ($lines as $i => $line) {
        if (preg_match('/^\s*(public\s+(static\s+)?function|final\s+class|abstract\s+class|class\s|interface\s|trait\s)/', $line) !== 1) {
            continue;
        }

        ++$total;

        // A docblock closes on one of the few lines immediately above the
        // declaration (attributes and blank lines may sit between them).
        $documented = false;
        for ($back = $i - 1; $back >= max(0, $i - 3); --$back) {
            if (str_contains($lines[$back], '*/')) {
                $documented = true;
                break;
            }
        }

        if (!$documented) {
            $missing[] = sprintf('%s:%d  %s', $relative, $i + 1, trim($line));
        }
    }
}

$documented = $total - count($missing);
printf("Public items: %d | documented: %d | missing: %d\n", $total, $documented, count($missing));

if ($missing !== []) {
    echo "\nMissing a docblock:\n";
    foreach ($missing as $entry) {
        printf("  %s\n", $entry);
    }
    echo "\nEvery public class, interface and method in the PHP SDK must carry a docblock —\n";
    echo "it is what phpDocumentor publishes as the API reference.\n";
    exit(1);
}

echo "All public items documented.\n";
exit(0);
