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
    /// <summary>Constructs a <see cref="PoisonMessageException"/> with no message.</summary>
    public PoisonMessageException()
    {
    }

    /// <summary>Constructs a <see cref="PoisonMessageException"/> with a diagnostic message.</summary>
    /// <param name="message">Describes why the delivery is being treated as poison.</param>
    public PoisonMessageException(string message)
        : base(message)
    {
    }

    /// <summary>Constructs a <see cref="PoisonMessageException"/> wrapping the underlying cause.</summary>
    /// <param name="message">Describes why the delivery is being treated as poison.</param>
    /// <param name="innerException">The exception the handler threw that triggered this poison classification.</param>
    public PoisonMessageException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
