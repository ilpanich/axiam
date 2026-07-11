<?php

declare(strict_types=1);

namespace Axiam\Sdk\Laravel;

use Axiam\Sdk\AxiamClient;

// D-01: the entire class definition is wrapped in a `class_exists` guard so that
// autoloading this file (which only ever happens because a real Laravel application
// listed it under `extra.laravel.providers` and Laravel's own package-discovery
// mechanism referenced it by name) never fatals if `illuminate/support` happens to be
// absent for any reason — a non-Laravel consumer of `axiam/axiam-sdk` never triggers
// Laravel's discovery mechanism at all, so this file is never even `require`d in that
// case (PSR-4 autoloading is lazy), but the guard is added as defense-in-depth per this
// plan's own `must_haves` (never assume the class is unreachable by name alone).
if (class_exists(\Illuminate\Support\ServiceProvider::class)) {
    /**
     * Auto-discovered Laravel bridge entry point (D-01): listed under `composer.json`
     * `extra.laravel.providers`, so a Laravel consumer gets this provider registered
     * with ZERO manual wiring beyond `composer require axiam/axiam-sdk` (true
     * zero-config auto-discovery, unlike the Symfony bridge which has no equivalent
     * mechanism without a published Flex recipe).
     *
     * `register()` binds a singleton {@see AxiamClient} configured from
     * `config('axiam.*')` (falling back to `AXIAM_*` environment variables so a
     * consumer never needs to publish a config file to get started). `boot()`
     * registers the `axiam.auth` middleware alias ({@see AxiamMiddleware}) and the
     * `axiam` Gate ability ({@see AxiamGate}, D-02) — `can:axiam,<resource>,<action>`
     * route middleware then works out of the box.
     */
    final class AxiamServiceProvider extends \Illuminate\Support\ServiceProvider
    {
        public function register(): void
        {
            $this->app->singleton(AxiamClient::class, static function ($app): AxiamClient {
                $config = $app->bound('config') ? $app->make('config') : null;

                $baseUrl = $config !== null
                    ? (string) $config->get('axiam.base_url', getenv('AXIAM_BASE_URL') ?: '')
                    : (string) (getenv('AXIAM_BASE_URL') ?: '');
                $tenant = $config !== null
                    ? (string) $config->get('axiam.tenant', getenv('AXIAM_TENANT') ?: '')
                    : (string) (getenv('AXIAM_TENANT') ?: '');
                $customCa = $config !== null
                    ? $config->get('axiam.custom_ca', getenv('AXIAM_CUSTOM_CA') ?: null)
                    : (getenv('AXIAM_CUSTOM_CA') ?: null);

                return new AxiamClient(
                    baseUrl: $baseUrl,
                    tenant: $tenant,
                    customCa: is_string($customCa) && $customCa !== '' ? $customCa : null,
                );
            });

            $this->app->singleton(AxiamMiddleware::class, function ($app): AxiamMiddleware {
                $config = $app->bound('config') ? $app->make('config') : null;
                $tenant = $config !== null
                    ? (string) $config->get('axiam.tenant', getenv('AXIAM_TENANT') ?: '')
                    : (string) (getenv('AXIAM_TENANT') ?: '');

                return new AxiamMiddleware($app->make(AxiamClient::class), $tenant);
            });

            $this->app->singleton(AxiamGate::class, static fn ($app): AxiamGate => new AxiamGate(
                $app->make(AxiamClient::class),
            ));
        }

        /**
         * Registers the `axiam.auth` route-middleware alias so applications can guard routes with
         * `->middleware('axiam.auth')` (D-02, §10) instead of referencing the middleware class.
         */
        public function boot(): void
        {
            // Route middleware alias — `->middleware('axiam.auth')` (D-02, §10).
            if ($this->app->bound('router')) {
                $this->app->make('router')->aliasMiddleware('axiam.auth', AxiamMiddleware::class);
            }

            // The `axiam` Gate ability — `can:axiam,<resource>,<action>` route
            // middleware (D-02). The server's additive-only RBAC is authoritative: this
            // callback never caches or overrides the decision, it is a one-line
            // delegation via {@see AxiamGate::allows()} -> {@see AxiamClient::can()}.
            if (class_exists(\Illuminate\Support\Facades\Gate::class)) {
                \Illuminate\Support\Facades\Gate::define(
                    'axiam',
                    fn ($user, string $resource, string $action): bool => $this->app
                        ->make(AxiamGate::class)
                        ->allows($resource, $action),
                );
            }
        }
    }
}
