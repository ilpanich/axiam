import { describe, it, expect, vi, afterEach } from "vitest";

import { cropToSquarePng, approximateDecodedBytes } from "./providerIcon";
import { PROVIDER_ICON_SIZE_PX } from "@/services/federation";

/**
 * jsdom implements neither image decoding nor a 2D canvas, so both are stubbed.
 * That is not a weaker test than the real thing would be: what matters here is
 * the *geometry* — which source rectangle is drawn, and that the result is a
 * PNG — and that is exactly what the stub can observe. Whether a browser's
 * canvas encodes a PNG correctly is not ours to assert.
 */

const REAL_IMAGE = globalThis.Image;

/** Install an `Image` whose load fires with the given intrinsic size. */
function stubImage(
  naturalWidth: number,
  naturalHeight: number,
  fail = false,
): void {
  class FakeImage {
    onload: (() => void) | null = null;
    onerror: (() => void) | null = null;
    naturalWidth = naturalWidth;
    naturalHeight = naturalHeight;
    set src(_value: string) {
      // The real one loads asynchronously; matching that is what keeps the
      // promise semantics under test rather than the stub's.
      queueMicrotask(() => (fail ? this.onerror?.() : this.onload?.()));
    }
  }
  // @ts-expect-error — replacing a DOM global for the duration of one test.
  globalThis.Image = FakeImage;
}

function stubCanvas(ctx: unknown, dataUrl = "data:image/png;base64,AAAA") {
  const drawImage = vi.fn();
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(
    (ctx === "real" ? { drawImage } : ctx) as never,
  );
  vi.spyOn(HTMLCanvasElement.prototype, "toDataURL").mockReturnValue(dataUrl);
  return drawImage;
}

function pngFile(): File {
  return new File([new Uint8Array([1, 2, 3, 4])], "logo.png", {
    type: "image/png",
  });
}

afterEach(() => {
  globalThis.Image = REAL_IMAGE;
  vi.restoreAllMocks();
});

describe("cropToSquarePng", () => {
  it("returns a PNG data URL at the size the server expects", async () => {
    stubImage(200, 200);
    stubCanvas("real");
    const out = await cropToSquarePng(pngFile());
    expect(out.startsWith("data:image/png;base64,")).toBe(true);
    expect(HTMLCanvasElement.prototype.toDataURL).toHaveBeenCalledWith(
      "image/png",
    );
  });

  /**
   * Centre-crop, not stretch: a wordmark squashed into a square is worse than
   * one with its ends trimmed. The offsets are the whole claim, so they are
   * what gets asserted.
   */
  it.each([
    ["landscape", 300, 100, 100, 100, 0],
    ["portrait", 100, 300, 100, 0, 100],
    ["already square", 120, 120, 120, 0, 0],
  ])(
    "centre-crops a %s source",
    async (_name, w, h, edge, sx, sy) => {
      stubImage(w, h);
      const drawImage = stubCanvas("real");
      await cropToSquarePng(pngFile());
      expect(drawImage).toHaveBeenCalledWith(
        expect.anything(),
        sx,
        sy,
        edge,
        edge,
        0,
        0,
        PROVIDER_ICON_SIZE_PX,
        PROVIDER_ICON_SIZE_PX,
      );
    },
  );

  it("rejects an image with no dimensions", async () => {
    stubImage(0, 0);
    stubCanvas("real");
    await expect(cropToSquarePng(pngFile())).rejects.toThrow(/empty image/);
  });

  it("rejects when the browser gives no 2D context", async () => {
    stubImage(64, 64);
    stubCanvas(null);
    await expect(cropToSquarePng(pngFile())).rejects.toThrow(/no canvas/);
  });

  it("rejects when the file is not a decodable image", async () => {
    stubImage(0, 0, true);
    await expect(cropToSquarePng(pngFile())).rejects.toThrow(/not an image/);
  });

  /** A canvas that throws mid-draw must reject, never resolve a partial icon. */
  it("rejects when drawing throws", async () => {
    stubImage(64, 64);
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue({
      drawImage: () => {
        throw new Error("tainted");
      },
    } as never);
    await expect(cropToSquarePng(pngFile())).rejects.toThrow(/tainted/);
  });

  it("rejects a non-Error thrown while drawing", async () => {
    stubImage(64, 64);
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue({
      drawImage: () => {
        throw "not an Error object";
      },
    } as never);
    await expect(cropToSquarePng(pngFile())).rejects.toThrow(/crop failed/);
  });

  it("rejects when the file cannot be read", async () => {
    stubImage(64, 64);
    stubCanvas("real");
    vi.spyOn(FileReader.prototype, "readAsDataURL").mockImplementation(
      function (this: FileReader) {
        queueMicrotask(() =>
          this.onerror?.(new ProgressEvent("error") as ProgressEvent<FileReader>),
        );
      },
    );
    await expect(cropToSquarePng(pngFile())).rejects.toThrow(/unreadable/);
  });
});

describe("approximateDecodedBytes", () => {
  /**
   * This is the cheap bound the field checks *before* decoding anything, so it
   * has to be right about padding — a value that reads low would let an
   * oversized icon reach the server and be refused there instead.
   */
  it.each([
    ["data:image/png;base64,AAAA", 3],
    ["data:image/png;base64,AAA=", 2],
    ["data:image/png;base64,AA==", 1],
    ["data:image/png;base64,AAAAAAAA", 6],
  ])("sizes %s as %i bytes", (url, expected) => {
    expect(approximateDecodedBytes(url)).toBe(expected);
  });

  it("reads a string with no payload separator as empty", () => {
    expect(approximateDecodedBytes("not-a-data-url")).toBe(0);
  });
});
