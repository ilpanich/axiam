<?php

declare(strict_types=1);

/**
 * examples/laravel_app/routes.php — the SC#4-Laravel runnable example: a protected
 * route demonstrating BOTH halves of D-02 in one place —
 *   1. Authentication: the `axiam.auth` middleware alias ({@see
 *      \Axiam\Sdk\Laravel\AxiamMiddleware}) verifies the bearer/cookie token locally
 *      (falling back to the shared single-flight refresh, §9/D-06) and returns 401 on
 *      any failure.
 *   2. Authorization: the `can:axiam,documents,read` Gate middleware ({@see
 *      \Axiam\Sdk\Laravel\AxiamGate}, registered by {@see
 *      \Axiam\Sdk\Laravel\AxiamServiceProvider::boot()}) calls
 *      `AxiamClient::can('documents', 'read')` and returns 403 on deny — Laravel's own
 *      built-in `can:` middleware (illuminate/auth's `Authorize` middleware) performs
 *      the deny -> 403 translation; this bridge never builds that response itself for
 *      the Gate-facade path (only {@see \Axiam\Sdk\Laravel\AxiamGate::authorize()}, a
 *      standalone alternative documented in README.md, returns a 403 directly).
 *
 * ZERO manual provider registration is required to reach this state (D-01): once a
 * Laravel application runs `composer require axiam/axiam-sdk`, Laravel's own
 * package-auto-discovery mechanism reads this package's `composer.json`
 * `extra.laravel.providers` entry and registers `AxiamServiceProvider` automatically —
 * nothing needs to be added to `config/app.php`'s `providers` array, and no
 * `bootstrap/providers.php` entry (Laravel 11+) is needed either. This file is
 * illustrative source (a real Laravel app would `require` it from `routes/web.php` or
 * `routes/api.php`) — it deliberately does not boot a full Laravel application (no
 * `illuminate/http`/`illuminate/auth`/`illuminate/routing` runtime dependency is
 * declared by this package, D-01), so it is validated here via `php -l` (a syntax
 * check), not executed as a live HTTP server. See README.md for the full zero-config
 * story, required env vars, and how to run this against a real Laravel installation.
 */

use Axiam\Sdk\Laravel\AxiamGate;
use Illuminate\Support\Facades\Route;

// --- Option A: the idiomatic Laravel Gate-facade route (Gate::define('axiam', ...),
//     registered automatically by AxiamServiceProvider::boot() — D-02, SC#4) ---------
Route::get('/documents/{id}', function (string $id) {
    return response()->json(['id' => $id, 'title' => 'Q3 Compliance Report']);
})->middleware(['axiam.auth', 'can:axiam,documents,read']);

// --- Option B: AxiamGate::authorize() called directly inside the route closure,
//     for apps that prefer not to depend on illuminate/auth's Gate/Authorize
//     middleware pipeline at all (still demonstrates auth 401 + authz 403, SC#4) ------
Route::get('/documents/{id}/standalone-gate', function (string $id, AxiamGate $gate) {
    $denied = $gate->authorize('documents', 'read');
    if ($denied !== null) {
        return $denied; // 403 AuthzError JSON body
    }

    return response()->json(['id' => $id, 'title' => 'Q3 Compliance Report']);
})->middleware(['axiam.auth']);
