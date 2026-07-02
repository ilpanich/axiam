<?php

declare(strict_types=1);

/**
 * examples/symfony_app/bundles.php — the MANUAL bundle registration Symfony requires
 * (Pitfall 5, D-01). Unlike the Laravel bridge (`extra.laravel.providers`, true
 * zero-config auto-discovery), Symfony has NO equivalent mechanism for a plain
 * `composer require` without a published Flex recipe (out of scope this phase) — a real
 * Symfony application MUST add this entry to its own `config/bundles.php` by hand. See
 * README.md for the full honest comparison and the accompanying `services.yaml` entry
 * that tags `AxiamAuthSubscriber`/`AxiamVoter` (also manual).
 *
 * This file is illustrative source, validated here via `php -l` (a syntax check) since
 * the core `axiam/axiam-sdk` package intentionally has zero `symfony/*` runtime
 * dependency (D-01) — it does not bundle a bootable Symfony kernel. Copy this array's
 * entry into your own application's `config/bundles.php`.
 */

return [
    Axiam\Sdk\Symfony\AxiamBundle::class => ['all' => true],
];
