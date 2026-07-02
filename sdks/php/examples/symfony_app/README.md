# AXIAM PHP SDK — Symfony example

Demonstrates the Symfony bridge (D-01/D-02, CONTRACT.md §10, SC#4): authentication via
`Axiam\Sdk\Symfony\AxiamAuthSubscriber` (a `kernel.request` event subscriber) and
authorization via `Axiam\Sdk\Symfony\AxiamVoter` — see [`bundles.php`](bundles.php) and
[`services.yaml`](services.yaml).

## No auto-discovery — manual registration is REQUIRED (Pitfall 5)

**Unlike the Laravel bridge, this integration is NOT zero-config.** Laravel's package
auto-discovery (`composer.json` `extra.laravel.providers`) registers
`Axiam\Sdk\Laravel\AxiamServiceProvider` automatically the moment you run
`composer require axiam/axiam-sdk` — see
[`../laravel_app/README.md`](../laravel_app/README.md). **Symfony has no equivalent
mechanism.** Symfony Flex *can* auto-configure a bundle via a published "recipe," but
that requires a separate pull request to the `symfony/recipes-contrib` repository —
out of scope for this phase. Without a published Flex recipe, a Symfony application
**must** perform two manual steps:

1. **Add the bundle to `config/bundles.php`** — copy the entry from
   [`bundles.php`](bundles.php) in this directory:

   ```php
   return [
       // ... your other bundles ...
       Axiam\Sdk\Symfony\AxiamBundle::class => ['all' => true],
   ];
   ```

2. **Tag the subscriber and voter in `config/services.yaml`** — `AxiamBundle` itself
   ships no container extension (see `src/Symfony/AxiamBundle.php`'s own doc comment),
   so registering the bundle alone does **not** wire the subscriber or voter. Copy the
   `services:` block from [`services.yaml`](services.yaml) in this directory into your
   own `config/services.yaml`:

   ```yaml
   services:
       Axiam\Sdk\AxiamClient:
           arguments:
               $baseUrl: '%env(AXIAM_BASE_URL)%'
               $tenant: '%env(AXIAM_TENANT)%'

       Axiam\Sdk\Symfony\AxiamAuthSubscriber:
           arguments:
               $client: '@Axiam\Sdk\AxiamClient'
               $tenant: '%env(AXIAM_TENANT)%'
           tags: ['kernel.event_subscriber']

       Axiam\Sdk\Symfony\AxiamVoter:
           arguments:
               $client: '@Axiam\Sdk\AxiamClient'
           tags: ['security.voter']
   ```

Do not describe this bridge as "auto-discovered" or "zero-config" anywhere in your own
documentation — it is genuinely a two-file manual registration, and that is an accurate,
supported way to integrate a Symfony bundle; it is simply a **different** developer
experience than the Laravel bridge, not a lesser-quality one.

| | Laravel bridge | Symfony bridge |
|---|---|---|
| Registration | Automatic (`extra.laravel.providers`) | Manual (`config/bundles.php` + `config/services.yaml`) |
| Steps required | 0 (beyond `composer require`) | 2 (bundle entry + service tags) |
| Why | Laravel's package-discovery mechanism reads `composer.json` directly | No Flex recipe published for this bundle in this phase |

## What each class does

| Config key | Env var | Required |
|---|---|---|
| `$baseUrl` (`AxiamClient` service arg) | `AXIAM_BASE_URL` | yes |
| `$tenant` (`AxiamClient`/`AxiamAuthSubscriber` service arg) | `AXIAM_TENANT` | yes (D-13 — AXIAM is multi-tenant, there is no default tenant) |
| `$customCa` (`AxiamClient` service arg) | `AXIAM_CUSTOM_CA` | no — a CA bundle **file path**; §6/D-12's ONLY TLS escape hatch, never a TLS-disable flag |

- **`Axiam\Sdk\Symfony\AxiamAuthSubscriber`** (authentication, D-02, §10): subscribes to
  `kernel.request` (`KernelEvents::REQUEST`). Extracts the bearer/cookie token, calls
  `AxiamClient::verifyLocallyOrFallback()` (local JWKS verification first, falling back
  to the shared single-flight refresh, §9/D-06), and either populates the
  `axiam_user` request attribute (`user_id`/`tenant_id`/`roles`) or short-circuits the
  request with a standardized `401` `JsonResponse` via `RequestEvent::setResponse()`.
  This bridge never re-implements JWKS/refresh logic — every security decision is made
  by `AxiamClient` itself.
- **`Axiam\Sdk\Symfony\AxiamVoter`** (authorization, D-02): `extends Voter`. `supports()`
  matches any `resource:action`-shaped attribute (e.g. `documents:read`);
  `voteOnAttribute()` delegates to `AxiamClient::can($resource, $action)` — the server's
  additive-only RBAC engine (allow-wins, default-deny, no explicit deny-override) is
  ALWAYS the authoritative decision-maker. A denied vote becomes Symfony's own
  `AccessDeniedException`, which Symfony's `AccessDeniedHandlerInterface` converts to a
  `403` response — this voter never builds an HTTP response itself.

## Both halves of SC#4 in one controller

```php
<?php
// src/Controller/DocumentController.php in your own Symfony application.
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

final class DocumentController extends AbstractController
{
    #[Route('/documents/{id}', methods: ['GET'])]
    public function show(string $id): JsonResponse
    {
        // 1. Authentication (AxiamAuthSubscriber, kernel.request): if this line is
        //    reached at all, the request already carries a verified token — a
        //    missing/invalid token was already short-circuited into a 401 upstream.
        //
        // 2. Authorization (AxiamVoter, security.voter): denyAccessUnlessGranted()
        //    calls AxiamVoter::voteOnAttribute('documents:read', ...) -> a denied vote
        //    throws AccessDeniedException, which Symfony's security system converts
        //    into a 403 response automatically.
        $this->denyAccessUnlessGranted('documents:read');

        return $this->json(['id' => $id, 'title' => 'Q3 Compliance Report']);
    }
}
```

- No `Authorization: Bearer <token>` header (and no `axiam_access` cookie) →
  `AxiamAuthSubscriber` sets a **401** `AuthError` `JsonResponse` before the controller
  ever runs.
- A valid token but `can('documents', 'read')` denies → `denyAccessUnlessGranted()`
  throws, Symfony's security layer returns **403**.
- A valid token and an allowed check → `200` with the document body.

## Running this against a real Symfony app

This directory ships as illustrative, `php -l`-clean source (the core `axiam/axiam-sdk`
package intentionally has **zero** `symfony/*` runtime dependency, D-01 — it does not
bundle a bootable Symfony kernel). To try it against a real Symfony installation:

```bash
composer create-project symfony/skeleton axiam-symfony-demo
cd axiam-symfony-demo
composer require symfony/security-bundle
composer config repositories.axiam-sdk path ../axiam/sdks/php
composer require axiam/axiam-sdk:@dev

# Manual step 1 (Pitfall 5): add the bundle entry from bundles.php to your own
# config/bundles.php.
# Manual step 2 (Pitfall 5): copy the services: block from services.yaml into your
# own config/services.yaml.

# Copy the controller above into src/Controller/DocumentController.php.

echo 'AXIAM_BASE_URL=https://localhost:8443' >> .env
echo 'AXIAM_TENANT=acme' >> .env

symfony server:start
curl -i http://127.0.0.1:8000/documents/doc-0001
# -> 401 AuthError (no token)
curl -i -H "Authorization: Bearer <valid-access-token>" http://127.0.0.1:8000/documents/doc-0001
# -> 200 (allowed) or 403 (denied) depending on the server's RBAC decision
```

No TLS-disable pattern appears anywhere in this example or the bridge itself — `verify`
defaults to strict TLS, and `AXIAM_CUSTOM_CA` (a CA bundle file path) is the only escape
hatch (§6/D-12).

## Contract conformance

This SDK conforms to CONTRACT.md §1–§10. See [`../../../CONTRACT.md`](../../../CONTRACT.md).
