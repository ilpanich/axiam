#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Standalone CLI worker entry point for the AXIAM AMQP consumer (SC#4).
 *
 * This is a long-running process, NOT a web request — it blocks on
 * Consumer::consume() until the connection drops or the process is killed.
 * There is no in-SDK auto-reconnect loop (Pitfall 6): on any connection
 * failure this script exits non-zero and relies on a process supervisor
 * (systemd, Kubernetes, supervisord, etc.) to restart it.
 *
 * Required environment variables:
 *   AXIAM_AMQP_SIGNING_KEY  - per-tenant AMQP HMAC signing secret
 *   AMQP_HOST               - RabbitMQ host
 *   AMQP_PORT               - RabbitMQ port (default 5672)
 *   AMQP_USER               - RabbitMQ username
 *   AMQP_PASS               - RabbitMQ password
 *   AMQP_VHOST              - RabbitMQ vhost (default /)
 *   AMQP_QUEUE              - queue name to consume
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\Amqp\AmqpDropMessage;
use Axiam\Sdk\Amqp\Consumer;

$signingKey = getenv('AXIAM_AMQP_SIGNING_KEY');
if ($signingKey === false || $signingKey === '') {
    fwrite(STDERR, "axiam-amqp-worker: AXIAM_AMQP_SIGNING_KEY is required\n");
    exit(1);
}

$host = getenv('AMQP_HOST') ?: 'localhost';
$port = (int) (getenv('AMQP_PORT') ?: 5672);
$user = getenv('AMQP_USER') ?: 'guest';
$pass = getenv('AMQP_PASS') ?: 'guest';
$vhost = getenv('AMQP_VHOST') ?: '/';
$queue = getenv('AMQP_QUEUE');
if ($queue === false || $queue === '') {
    fwrite(STDERR, "axiam-amqp-worker: AMQP_QUEUE is required\n");
    exit(1);
}

$consumer = new Consumer(signingKey: $signingKey);

try {
    $consumer->consume(
        host: $host,
        port: $port,
        user: $user,
        pass: $pass,
        vhost: $vhost,
        queue: $queue,
        handler: function (array $event): void {
            // Application-specific handling of the verified, HMAC-checked
            // event. Throw AmqpDropMessage for poison messages that must
            // never be requeued.
            if (!isset($event['action'])) {
                throw new AmqpDropMessage('event missing required "action" field');
            }
            fwrite(STDOUT, sprintf("[axiam-amqp-worker] handled event action=%s\n", $event['action']));
        }
    );
} catch (\Throwable $e) {
    // No in-SDK auto-reconnect (Pitfall 6) — exit non-zero so a process
    // supervisor restarts the worker.
    fwrite(STDERR, sprintf("axiam-amqp-worker: connection failure: %s\n", $e->getMessage()));
    exit(1);
}

exit(0);
