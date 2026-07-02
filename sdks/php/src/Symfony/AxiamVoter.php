<?php

declare(strict_types=1);

namespace Axiam\Sdk\Symfony;

use Axiam\Sdk\AxiamClient;

// D-01: the entire class definition is wrapped in a `class_exists` guard (mirrors the
// Laravel `AxiamServiceProvider`'s wrapper, defense-in-depth) so this file never fatals
// if `symfony/security-core` happens to be absent — a non-Symfony consumer of
// `axiam/axiam-sdk` never references this class by name, so PSR-4's lazy autoloading
// never even `require`s this file in that case.
if (class_exists(\Symfony\Component\Security\Core\Authorization\Voter\Voter::class)) {
    /**
     * Symfony authorization voter (D-02, CONTRACT.md §1/§10): a one-line delegation to
     * {@see AxiamClient::can()} — the server's additive-only RBAC engine (allow-wins,
     * default-deny, no explicit deny-override) is ALWAYS the authoritative
     * decision-maker. This class never caches a decision beyond the token's own TTL and
     * never implements a client-side deny-override (project RBAC constraint,
     * CLAUDE.md).
     *
     * `supports()` matches any `resource:action`-shaped attribute (e.g.
     * `is_granted('documents:read')` / `#[IsGranted('documents:read')]`); Symfony's own
     * `AccessDeniedException` (thrown by `denyAccessUnlessGranted()`/`#[IsGranted]` on a
     * denied vote) is what a real Symfony app turns into a 403 response via its
     * `AccessDeniedHandlerInterface` — this class only ever returns the boolean vote,
     * never builds an HTTP response itself.
     *
     * MUST be manually registered (Pitfall 5): tag this class `security.voter` in the
     * consuming app's own `config/services.yaml` — see `examples/symfony_app/`.
     *
     * @extends \Symfony\Component\Security\Core\Authorization\Voter\Voter<string, mixed>
     */
    final class AxiamVoter extends \Symfony\Component\Security\Core\Authorization\Voter\Voter
    {
        public function __construct(private readonly AxiamClient $client)
        {
        }

        protected function supports(string $attribute, mixed $subject): bool
        {
            return str_contains($attribute, ':');
        }

        protected function voteOnAttribute(
            string $attribute,
            mixed $subject,
            \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token,
            ?\Symfony\Component\Security\Core\Authorization\Voter\Vote $vote = null,
        ): bool {
            [$resource, $action] = explode(':', $attribute, 2);

            // Server's additive-only RBAC is authoritative — no client-side
            // deny-override, no caching beyond the token's own remaining TTL.
            return $this->client->can($resource, $action);
        }
    }
}
