<?php

declare(strict_types=1);

namespace Axiam\Sdk\Symfony;

// D-01: guarded exactly like the Laravel `AxiamServiceProvider`'s `class_exists` wrapper
// (defense-in-depth) — PSR-4 autoloading is already lazy, so this file is only ever
// `require`d when a real Symfony application's own `config/bundles.php` explicitly
// references `Axiam\Sdk\Symfony\AxiamBundle::class` by name. Unlike Laravel's
// `extra.laravel.providers` auto-discovery, Symfony has NO equivalent zero-config
// mechanism for a plain `composer require` without a published Flex recipe (out of
// scope this phase, Pitfall 5) — this bundle MUST be manually listed in
// `config/bundles.php`, and `AxiamAuthSubscriber`/`AxiamVoter` MUST be manually tagged in
// the consuming app's own `config/services.yaml` (see `examples/symfony_app/`).
if (class_exists(\Symfony\Component\HttpKernel\Bundle\Bundle::class)) {
    /**
     * The Symfony bundle bootstrap. This class intentionally carries no container
     * extension of its own — `AxiamAuthSubscriber` (`kernel.event_subscriber`) and
     * `AxiamVoter` (`security.voter`) are wired via the consuming application's OWN
     * `config/services.yaml` (manual registration, Pitfall 5), exactly like the
     * `config/bundles.php` entry that registers this bundle itself. Registering this
     * class is what tells Symfony's kernel the AXIAM SDK bundle is present; it performs
     * no additional auto-wiring beyond that on its own.
     */
    final class AxiamBundle extends \Symfony\Component\HttpKernel\Bundle\Bundle
    {
    }
}
