<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

use PhpAmqpLib\Channel\AMQPChannel;
use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Message\AMQPMessage;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * php-amqplib blocking consume loop with HMAC verify-before-handler
 * (sdks/CONTRACT.md §8, D-04).
 *
 * This is NOT a web-request path — `consume()` blocks on `$channel->wait()`
 * for the lifetime of the process. It is meant to run on a long-running
 * runtime (a dedicated CLI worker process), restarted by a process
 * supervisor on exit (see bin/axiam-amqp-worker.php — no in-SDK
 * auto-reconnect loop, Pitfall 6).
 *
 * Ack/nack semantics (verifyAndDispatch):
 *   - HMAC verification failure           -> nack WITHOUT requeue (fail closed, poison-loop risk)
 *   - NEW-4 replay-protection gate failure -> nack WITHOUT requeue (fail closed, same as HMAC failure)
 *   - Handler throws AmqpDropMessage       -> nack WITHOUT requeue (application-declared poison message)
 *   - Handler throws any other \Throwable  -> nack WITH requeue (transient failure, retry)
 *   - Handler completes successfully       -> ack
 *
 * NEW-4 (CONTRACT.md §8 "v2 — Replay Protection", hard cutover): once the
 * HMAC verifies, the delivery is ADDITIONALLY rejected (same nack-without-
 * requeue path) when `key_version < 2`, `issued_at` falls outside the
 * ±skew freshness window, or `nonce` has already been seen. Because
 * Hmac::verify re-serializes the decoded body (minus `hmac_signature`) in
 * insertion order (Pitfall 5), `nonce`/`issued_at` are already covered by
 * the verified HMAC bytes with NO canonicalization change — only the
 * {@see ReplayGuard} gates are new. See ReplayGuard for the full policy.
 */
final class Consumer
{
    private ?AMQPStreamConnection $connection = null;
    private ?AMQPChannel $channel = null;

    /**
     * ONE ReplayGuard shared across every delivery handled by this Consumer
     * instance for the lifetime of the process (NEW-4) — constructing a
     * fresh guard per delivery would defeat nonce-replay dedup entirely.
     */
    private readonly ReplayGuard $replayGuard;

    /**
     * @param int $skewSeconds Freshness window (seconds) applied to a
     *        delivery's `issued_at` (NEW-4); also sets the nonce dedup TTL
     *        (2×skewSeconds). Defaults to
     *        {@see ReplayGuard::DEFAULT_SKEW_SECONDS} (300s / 5 minutes),
     *        matching the server's DEFAULT_FRESHNESS_SKEW_SECS. Ignored
     *        when $replayGuard is supplied.
     * @param ReplayGuard|null $replayGuard Inject a preconfigured guard
     *        (e.g. with a fixed clock) for deterministic tests; when null a
     *        guard is constructed from $skewSeconds.
     */
    public function __construct(
        private readonly string $signingKey,
        private readonly LoggerInterface $logger = new NullLogger(),
        int $skewSeconds = ReplayGuard::DEFAULT_SKEW_SECONDS,
        ?ReplayGuard $replayGuard = null,
    ) {
        $this->replayGuard = $replayGuard ?? new ReplayGuard($skewSeconds);
    }

    /**
     * @param callable(array<string, mixed>): void $handler Throws AmqpDropMessage
     *        for poison messages that must never be requeued.
     */
    public function consume(
        string $host,
        int $port,
        string $user,
        string $pass,
        string $vhost,
        string $queue,
        callable $handler,
    ): void {
        $this->connection = new AMQPStreamConnection($host, $port, $user, $pass, $vhost);
        $this->channel = $this->connection->channel();
        $this->channel->basic_qos(0, 10, false);

        $this->channel->basic_consume(
            $queue,
            '',
            false,
            false,
            false,
            false,
            function (AMQPMessage $msg) use ($handler): void {
                $channel = $msg->getChannel();
                $tag = $msg->getDeliveryTag();

                $this->verifyAndDispatch(
                    $msg->getBody(),
                    $handler,
                    ack: static fn (): mixed => $channel->basic_ack($tag),
                    nackNoRequeue: static fn (): mixed => $channel->basic_nack($tag, false, false),
                    nackRequeue: static fn (): mixed => $channel->basic_nack($tag, false, true),
                );
            }
        );

        while ($this->channel->is_consuming()) {
            $this->channel->wait(); // blocking loop — not a web-request path (D-04)
        }
    }

    /**
     * Verifies a single delivery's HMAC signature BEFORE the handler ever
     * sees it (D-04), then applies the NEW-4 replay-protection gate, then
     * maps the outcome to the ack/nack matrix documented on the class.
     *
     * Extracted from the `basic_consume` closure so it is a separately
     * testable unit — tests can drive it with fake ack/nack callables
     * without a live broker or AMQPMessage.
     *
     * @param callable(array<string, mixed>): void $handler
     * @param callable(): mixed $ack
     * @param callable(): mixed $nackNoRequeue
     * @param callable(): mixed $nackRequeue
     */
    public function verifyAndDispatch(
        string $body,
        callable $handler,
        callable $ack,
        callable $nackNoRequeue,
        callable $nackRequeue,
    ): void {
        // Verify BEFORE the handler ever sees the message (D-04) — the
        // handler must never run against an unverified/tampered body.
        if (!Hmac::verify($this->signingKey, $body)) {
            // §8.3: never log the signature value or message body on failure.
            $this->logger->warning('axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue');
            $nackNoRequeue(); // fail closed, no requeue
            return;
        }

        $event = json_decode($body, true);
        unset($event['hmac_signature']);

        // NEW-4: only reached once the HMAC has verified. $event was
        // decoded from the exact wire bytes that were just verified, so
        // nonce/issued_at are already inside the checked HMAC — this is an
        // ADDITIONAL validation gate, not re-verification.
        $rejectReason = $this->replayGuard->check(is_array($event) ? $event : []);
        if ($rejectReason !== null) {
            // §8.4/NEW-4 security event: fact of rejection only, never the
            // nonce/issued_at/HMAC values.
            $this->logger->warning(
                "axiam_sdk_security: AMQP v2 replay-protection check failed ({$rejectReason}); nacking without requeue"
            );
            $nackNoRequeue(); // fail closed, no requeue
            return;
        }

        try {
            $handler($event);
            $ack();
        } catch (AmqpDropMessage) {
            $nackNoRequeue(); // poison -> no requeue
        } catch (\Throwable) {
            $nackRequeue(); // transient -> requeue
        }
    }
}
