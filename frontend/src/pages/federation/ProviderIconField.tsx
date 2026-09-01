import { useRef, useState } from "react";
import { ImagePlus, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  MAX_PROVIDER_ICON_BYTES,
  MAX_PROVIDER_ICON_SOURCE_BYTES,
  PROVIDER_ICON_SIZE_PX,
} from "@/services/federation";

import { approximateDecodedBytes, cropToSquarePng } from "./providerIcon";

/**
 * Upload a custom sign-in-button icon for a generic provider.
 *
 * # Why it crops rather than storing what was picked
 *
 * The stored icon is served by an **unauthenticated** endpoint on every render
 * of a login page. Storing whatever an operator happened to have on their
 * desktop would put a two-megabyte photograph in front of every visitor, and
 * would render at whatever aspect ratio it happened to have, next to five marks
 * that are all square. So the file never reaches the server: the browser draws
 * it onto a {@link PROVIDER_ICON_SIZE_PX}-square canvas — centre-cropped to the
 * shorter edge, so nothing is stretched — and what is uploaded is the PNG that
 * comes out. That is normally a few kilobytes.
 *
 * # Why there is a client-side size limit *as well*
 *
 * The server's limit is on the finished icon, and the crop all but guarantees
 * the result is under it. The limit here is on the **source file**, and it
 * exists for a different reason: decoding a 200 MB TIFF locks the tab. Failing
 * on the file size before touching a canvas turns that into a sentence.
 *
 * Only the `generic_*` kinds get this control. Google, Apple and Microsoft
 * publish sign-in-button rules that require their own mark, so the server
 * refuses a custom icon for them and the admin UI does not offer one.
 */

export interface ProviderIconFieldProps {
  /** Current icon as a `data:` URL, or empty for none. */
  value: string;
  onChange: (dataUrl: string) => void;
  idPrefix: string;
  /** Shown beside the icon so the operator sees what the button will read. */
  displayName: string;
}

/** Accepted source types. Mirrors the server's raster-only rule. */
const ACCEPT = "image/png,image/jpeg,image/webp,image/gif,image/avif";

export function ProviderIconField({
  value,
  onChange,
  idPrefix,
  displayName,
}: ProviderIconFieldProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const inputId = `${idPrefix}-button-icon`;
  const errorId = `${inputId}-error`;

  async function handleFile(file: File) {
    setError(null);
    if (file.size > MAX_PROVIDER_ICON_SOURCE_BYTES) {
      setError(
        `That image is ${Math.ceil(file.size / 1024 / 1024)} MB. Pick one under ${
          MAX_PROVIDER_ICON_SOURCE_BYTES / 1024 / 1024
        } MB.`,
      );
      return;
    }
    try {
      const dataUrl = await cropToSquarePng(file);
      // Belt to the crop's braces. The canvas output is normally a few
      // kilobytes, but a noisy photograph at 64×64 can still surprise, and the
      // server would reject it — better to say so here than to have the save
      // fail with a message about base64.
      if (approximateDecodedBytes(dataUrl) > MAX_PROVIDER_ICON_BYTES) {
        setError(
          `That image still comes out over ${MAX_PROVIDER_ICON_BYTES / 1024} KiB after cropping. Try a simpler logo.`,
        );
        return;
      }
      onChange(dataUrl);
    } catch {
      setError("That file could not be read as an image.");
    }
  }

  return (
    <div className="space-y-2">
      <Label htmlFor={inputId}>Button icon</Label>
      <div className="flex items-center gap-3">
        <div
          className="flex h-12 w-12 shrink-0 items-center justify-center overflow-hidden rounded-md border border-primary/20 bg-white/5"
          aria-hidden="true"
        >
          {value ? (
            <img
              src={value}
              alt=""
              className="h-full w-full object-contain"
            />
          ) : (
            <ImagePlus size={18} className="text-muted-foreground" />
          )}
        </div>
        <div className="flex flex-1 flex-wrap items-center gap-2">
          <input
            ref={inputRef}
            id={inputId}
            type="file"
            accept={ACCEPT}
            className="sr-only"
            aria-describedby={error ? errorId : `${inputId}-help`}
            onChange={(e) => {
              const file = e.target.files?.[0];
              // Cleared so picking the same file twice fires `change` again —
              // otherwise a failed upload cannot be retried without choosing a
              // different file.
              e.target.value = "";
              if (file) void handleFile(file);
            }}
          />
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => inputRef.current?.click()}
          >
            {value ? "Replace icon" : "Upload icon"}
          </Button>
          {value && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                setError(null);
                onChange("");
              }}
            >
              <Trash2 size={14} aria-hidden="true" />
              Remove
            </Button>
          )}
        </div>
      </div>
      {error ? (
        <p id={errorId} role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : (
        <p id={`${inputId}-help`} className="text-xs text-muted-foreground">
          Optional. Cropped to {PROVIDER_ICON_SIZE_PX}×{PROVIDER_ICON_SIZE_PX}{" "}
          and shown beside &ldquo;Sign in with{" "}
          {displayName.trim() || "this provider"}&rdquo; on the login page.
          Without one, a neutral icon is used.
        </p>
      )}
    </div>
  );
}
