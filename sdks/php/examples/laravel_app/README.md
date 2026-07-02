# AXIAM PHP SDK — Laravel example

Demonstrates the first-class, **auto-discovered** Laravel bridge (D-01/D-02, CONTRACT.md
§10, SC#4): authentication via the `axiam.auth` middleware alias and authorization via
the `can:axiam,<resource>,<action>` Gate — see [`routes.php`](routes.php).

## Zero-config auto-discovery (D-01)

**No manual provider registration is required.** Once your Laravel application runs:

```bash
composer require axiam/axiam-sdk
```

Laravel's own [package auto-discovery](https://laravel.com/docs/packages#package-discovery)
mechanism reads this package's `composer.json`:

```json
{
  "extra": {
    "laravel": {
      "providers": ["Axiam\\Sdk\\Laravel\\AxiamServiceProvider"]
    }
  }
}
```

and registers `Axiam\Sdk\Laravel\AxiamServiceProvider` automatically. You do **not**
need to add anything to `config/app.php`'s `providers` array, and you do **not** need a
`bootstrap/providers.php` entry (Laravel 11+) either. This is the accurate half of D-01's
"first-class, auto-discovered bridges" — the Symfony bridge (`sdks/php/src/Symfony/`) has
no equivalent zero-config mechanism without a published Flex recipe, and its README says
so explicitly; do not assume Symfony gets the same experience.

## What the ServiceProvider registers

`AxiamServiceProvider::register()` binds a singleton `Axiam\Sdk\AxiamClient` from
`config('axiam.*')`, falling back to environment variables so you never need to publish a
config file to get started:

| Config key         | Env var             | Required |
|---------------------|----------------------|----------|
| `axiam.base_url`    | `AXIAM_BASE_URL`     | yes      |
| `axiam.tenant`      | `AXIAM_TENANT`       | yes (D-13 — AXIAM is multi-tenant, there is no default tenant) |
| `axiam.custom_ca`   | `AXIAM_CUSTOM_CA`    | no — a CA bundle **file path**; §6/D-12's ONLY TLS escape hatch, never a TLS-disable flag |

`AxiamServiceProvider::boot()` registers:

- The **`axiam.auth`** route-middleware alias → `Axiam\Sdk\Laravel\AxiamMiddleware`
  (authentication, D-02): verifies the bearer/cookie token locally via
  `AxiamClient::verifyLocallyOrFallback()` (JWKS verification first, falling back to the
  shared single-flight refresh, §9/D-06), populates the `axiam_user` request attribute
  (`user_id`/`tenant_id`/`roles`), and returns a standardized `401` JSON error body on any
  failure. This bridge never re-implements JWKS/refresh logic — every security decision
  is made by `AxiamClient` itself.
- The **`axiam`** Gate ability (authorization, D-02): `can:axiam,<resource>,<action>`
  route middleware calls `AxiamClient::can($resource, $action)` — Laravel's own built-in
  `Authorize` middleware converts a deny into a `403` response. The server's
  additive-only RBAC engine (allow-wins, default-deny, no explicit deny-override) is
  ALWAYS the authoritative decision-maker; this bridge never caches a decision beyond the
  token's own TTL and never overrides it client-side.

## Both halves of SC#4 in one route (`routes.php`)

```php
Route::get('/documents/{id}', function (string $id) {
    return response()->json(['id' => $id, 'title' => 'Q3 Compliance Report']);
})->middleware(['axiam.auth', 'can:axiam,documents,read']);
```

- No `Authorization: Bearer <token>` header (and no `axiam_access` cookie) → **401**
  (`axiam.auth`).
- A valid token but `can('documents', 'read')` denies → **403** (`can:axiam,...`).
- A valid token and an allowed check → `200` with the document body.

A second route in the same file (`/documents/{id}/standalone-gate`) shows
`Axiam\Sdk\Laravel\AxiamGate::authorize()` called directly inside the route closure — for
applications that prefer not to depend on Laravel's `illuminate/auth` Gate/`Authorize`
middleware pipeline at all, it returns the `403` `JsonResponse` itself.

## Running this against a real Laravel app

This directory ships as illustrative, `php -l`-clean source (the core `axiam/axiam-sdk`
package intentionally has **zero** `illuminate/*` runtime dependency, D-01 — it does not
bundle a bootable Laravel application). To try it against a real Laravel installation:

```bash
composer create-project laravel/laravel axiam-laravel-demo
cd axiam-laravel-demo
composer config repositories.axiam-sdk path ../axiam/sdks/php
composer require axiam/axiam-sdk:@dev

# Copy this example's routes into your app:
cat ../axiam/sdks/php/examples/laravel_app/routes.php >> routes/web.php

# Configure the client:
echo 'AXIAM_BASE_URL=https://localhost:8443' >> .env
echo 'AXIAM_TENANT=acme' >> .env

php artisan serve
curl -i http://127.0.0.1:8000/documents/doc-0001
# -> 401 AuthError (no token)
curl -i -H "Authorization: Bearer <valid-access-token>" http://127.0.0.1:8000/documents/doc-0001
# -> 200 (allowed) or 403 AuthzError (denied) depending on the server's RBAC decision
```

No TLS-disable pattern appears anywhere in this example or the bridge itself — `verify`
defaults to strict TLS, and `AXIAM_CUSTOM_CA` (a CA bundle file path) is the only escape
hatch (§6/D-12).

## Contract conformance

This SDK conforms to CONTRACT.md §1–§10. See [`../../../CONTRACT.md`](../../../CONTRACT.md).
