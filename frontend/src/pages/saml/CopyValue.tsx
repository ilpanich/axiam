import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Copy `text`, through the async clipboard API where there is one, else a hidden textarea. */
async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const el = document.createElement("textarea");
  el.value = text;
  el.style.position = "fixed";
  el.style.top = "-9999px";
  document.body.appendChild(el);
  el.select();
  document.execCommand("copy");
  document.body.removeChild(el);
}

/**
 * A value an administrator pastes into another system (an entity id, a
 * metadata URL, a fingerprint), with a copy button that names what it copies.
 */
export function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await copyText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be denied; the value stays selectable on screen.
      setCopied(false);
    }
  }

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <code className="text-xs break-all">{value}</code>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        aria-label={`Copy ${label}`}
        onClick={handleCopy}
      >
        {copied ? (
          <Check size={14} aria-hidden="true" />
        ) : (
          <Copy size={14} aria-hidden="true" />
        )}
      </Button>
      <span className="sr-only" role="status">
        {copied ? `${label} copied` : ""}
      </span>
    </span>
  );
}
