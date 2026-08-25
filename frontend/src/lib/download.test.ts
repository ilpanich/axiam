import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { certificateFilename, downloadTextFile } from "./download";

describe("certificateFilename", () => {
  it("turns an X.500 subject into something a filesystem accepts", () => {
    // Slashes are path separators, colons are reserved on Windows and were the
    // separator on classic macOS, and a comma-and-space DN would produce a name
    // no shell can pass around unquoted.
    expect(certificateFilename("CN=device-001, OU=Fleet/EU", "crt")).toBe(
      "device-001-OU-Fleet-EU.crt"
    );
  });

  it("drops a leading CN= so the file is named after the thing, not the syntax", () => {
    expect(certificateFilename("CN=Acme Root CA", "pem")).toBe(
      "Acme-Root-CA.pem"
    );
  });

  it("falls back rather than producing a dotfile", () => {
    // A subject of nothing but punctuation would otherwise yield ".crt", which
    // most file managers hide and most users never find again.
    expect(certificateFilename("///", "crt")).toBe("certificate.crt");
    expect(certificateFilename("", "crt")).toBe("certificate.crt");
  });

  it("caps the stem so an absurd DN cannot exceed a filesystem's name limit", () => {
    const name = certificateFilename("CN=" + "x".repeat(500), "crt");
    expect(name.length).toBeLessThanOrEqual(84);
    expect(name.endsWith(".crt")).toBe(true);
  });
});

describe("downloadTextFile", () => {
  const createObjectURL = vi.fn(() => "blob:fake");
  const revokeObjectURL = vi.fn();

  beforeEach(() => {
    vi.useFakeTimers();
    createObjectURL.mockClear();
    revokeObjectURL.mockClear();
    vi.stubGlobal("URL", {
      ...URL,
      createObjectURL,
      revokeObjectURL,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("clicks an anchor that is actually in the document", () => {
    // Firefox silently ignores a click on a detached anchor, so the element has
    // to be appended first — and removed after, or every download leaves a node
    // behind.
    const appended: Node[] = [];
    const appendSpy = vi
      .spyOn(document.body, "appendChild")
      .mockImplementation((node) => {
        appended.push(node);
        return node;
      });
    const removeSpy = vi
      .spyOn(document.body, "removeChild")
      .mockImplementation((node) => node);
    const clickSpy = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(clickSpy);

    downloadTextFile("acme.crt", "-----BEGIN CERTIFICATE-----\n");

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(appended).toHaveLength(1);
    const anchor = appended[0] as HTMLAnchorElement;
    expect(anchor.download).toBe("acme.crt");
    expect(anchor.href).toContain("blob:fake");
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(removeSpy).toHaveBeenCalledTimes(1);

    // Revocation is deferred: doing it synchronously races the download in
    // Safari, which has not necessarily read the blob when click() returns.
    expect(revokeObjectURL).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:fake");

    appendSpy.mockRestore();
    removeSpy.mockRestore();
  });
});
