import { PROVIDER_ICON_SIZE_PX } from "@/services/federation";

/**
 * Cropping and sizing for a custom sign-in-button icon.
 *
 * Split from `ProviderIconField` because these are plain functions rather than
 * components — which is also what lets them be unit-tested against a canvas
 * without rendering anything.
 */

/**
 * Centre-crop an image file to a {@link PROVIDER_ICON_SIZE_PX} square PNG.
 *
 * Centre-crop rather than stretch: a wordmark squashed into a square is worse
 * than a wordmark with its ends trimmed, and an operator can see the result
 * before saving either way.
 */
export function cropToSquarePng(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("unreadable"));
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error("not an image"));
      img.onload = () => {
        try {
          const edge = Math.min(img.naturalWidth, img.naturalHeight);
          if (!edge) {
            reject(new Error("empty image"));
            return;
          }
          const canvas = document.createElement("canvas");
          canvas.width = PROVIDER_ICON_SIZE_PX;
          canvas.height = PROVIDER_ICON_SIZE_PX;
          const ctx = canvas.getContext("2d");
          if (!ctx) {
            reject(new Error("no canvas"));
            return;
          }
          ctx.drawImage(
            img,
            (img.naturalWidth - edge) / 2,
            (img.naturalHeight - edge) / 2,
            edge,
            edge,
            0,
            0,
            PROVIDER_ICON_SIZE_PX,
            PROVIDER_ICON_SIZE_PX,
          );
          // PNG, always: it is lossless for the flat-colour logos this is for,
          // it keeps transparency (a JPEG would paint a black square behind a
          // transparent mark), and it is one of the three types the server
          // accepts.
          resolve(canvas.toDataURL("image/png"));
        } catch (e) {
          reject(e instanceof Error ? e : new Error("crop failed"));
        }
      };
      img.src = String(reader.result);
    };
    reader.readAsDataURL(file);
  });
}

/** Decoded byte count for a base64 data URL, close enough for a bound check. */
export function approximateDecodedBytes(dataUrl: string): number {
  const comma = dataUrl.indexOf(",");
  if (comma < 0) return 0;
  const payload = dataUrl.slice(comma + 1);
  const padding = payload.endsWith("==") ? 2 : payload.endsWith("=") ? 1 : 0;
  return Math.floor(payload.length / 4) * 3 - padding;
}
