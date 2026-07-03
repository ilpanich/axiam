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
 * Three-way ack/nack semantics:
 *   - HMAC verification failure           -> nack WITHOUT requeue (fail closed, poison-loop risk)
 *   - Handler throws AmqpDropMessage       -> nack WITHOUT requeue (application-declared poison message)
 *   - Handler throws any other \Throwable  -> nack WITH requeue (transient failure, retry)
 *   - Handler completes successfully       -> ack
 */
final class Consumer
{
    private ?AMQPStreamConnection $connection = null;
    private ?AMQPChannel $channel = null;

    public function __construct(
        private readonly string $signingKey,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
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
                // Verify BEFORE the handler ever sees the message (D-04) — the
                // handler must never run against an unverified/tampered body.
                if (!Hmac::verify($this->signingKey, $msg->getBody())) {
                    // §8.3: never log the signature value or message body on failure.
                    $this->logger->warning('axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue');
                    $msg->getChannel()->basic_nack($msg->getDeliveryTag(), false, false); // fail closed, no requeue
                    return;
                }

                $event = json_decode($msg->getBody(), true);
                unset($event['hmac_signature']);

                try {
                    $handler($event);
                    $msg->getChannel()->basic_ack($msg->getDeliveryTag());
                } catch (AmqpDropMessage) {
                    $msg->getChannel()->basic_nack($msg->getDeliveryTag(), false, false); // poison -> no requeue
                } catch (\Throwable) {
                    $msg->getChannel()->basic_nack($msg->getDeliveryTag(), false, true); // transient -> requeue
                }
            }
        );

        while ($this->channel->is_consuming()) {
            $this->channel->wait(); // blocking loop — not a web-request path (D-04)
        }
    }
}
