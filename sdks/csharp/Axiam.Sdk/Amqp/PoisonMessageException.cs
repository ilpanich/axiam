using System;

namespace Axiam.Sdk.Amqp;

/// <summary>
/// Poison-message sentinel a consumer-supplied handler throws to signal that
/// the current delivery must be nacked <b>without</b> requeue, rather than
/// the default nack-with-requeue applied to any other handler exception
/// (D-11, <c>sdks/CONTRACT.md</c> §8). Mirrors the Go <c>ErrDrop</c> sentinel
/// / Java <c>ErrDrop</c> exception used by the sibling SDKs.
/// </summary>
public sealed class PoisonMessageException : Exception
{
    public PoisonMessageException()
    {
    }

    public PoisonMessageException(string message)
        : base(message)
    {
    }

    public PoisonMessageException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
