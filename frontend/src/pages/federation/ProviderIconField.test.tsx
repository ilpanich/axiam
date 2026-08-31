import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const cropToSquarePng = vi.fn();
const approximateDecodedBytes = vi.fn();
vi.mock("./providerIcon", () => ({
  cropToSquarePng: (f: File) => cropToSquarePng(f),
  approximateDecodedBytes: (u: string) => approximateDecodedBytes(u),
}));

import { ProviderIconField } from "./ProviderIconField";
import {
  MAX_PROVIDER_ICON_BYTES,
  MAX_PROVIDER_ICON_SOURCE_BYTES,
  PROVIDER_ICON_SIZE_PX,
} from "@/services/federation";

const CROPPED = "data:image/png;base64,AAAA";

function file(name = "logo.png", size = 1024): File {
  const f = new File([new Uint8Array([1, 2, 3])], name, { type: "image/png" });
  // `File` computes its own size from the parts; override it so a test can name
  // a 200 MB file without allocating one.
  Object.defineProperty(f, "size", { value: size });
  return f;
}

function setup(value = "") {
  const onChange = vi.fn();
  render(
    <ProviderIconField
      value={value}
      onChange={onChange}
      idPrefix="create"
      displayName="Acme SSO"
    />,
  );
  return { onChange, input: screen.getByLabelText("Button icon") };
}

beforeEach(() => {
  vi.clearAllMocks();
  cropToSquarePng.mockResolvedValue(CROPPED);
  approximateDecodedBytes.mockReturnValue(64);
});

describe("ProviderIconField", () => {
  it("hands the cropped PNG back, not the file that was picked", async () => {
    const { onChange, input } = setup();
    await userEvent.upload(input, file());
    expect(cropToSquarePng).toHaveBeenCalled();
    await vi.waitFor(() => expect(onChange).toHaveBeenCalledWith(CROPPED));
  });

  /**
   * The source limit exists for a different reason than the server's: decoding
   * a 200 MB TIFF locks the tab, and failing on the file size before touching a
   * canvas turns that into a sentence.
   */
  it("refuses an oversized source file without decoding it", async () => {
    const { onChange, input } = setup();
    await userEvent.upload(input, file("huge.png", MAX_PROVIDER_ICON_SOURCE_BYTES + 1));

    expect(await screen.findByRole("alert")).toHaveTextContent(/Pick one under/);
    expect(cropToSquarePng).not.toHaveBeenCalled();
    expect(onChange).not.toHaveBeenCalled();
  });

  /** Belt to the crop's braces: a noisy photograph can still come out large. */
  it("refuses a crop that is still over the stored bound", async () => {
    approximateDecodedBytes.mockReturnValue(MAX_PROVIDER_ICON_BYTES + 1);
    const { onChange, input } = setup();
    await userEvent.upload(input, file());

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /still comes out over/,
    );
    expect(onChange).not.toHaveBeenCalled();
  });

  it("reports a file that is not a decodable image", async () => {
    cropToSquarePng.mockRejectedValue(new Error("not an image"));
    const { onChange, input } = setup();
    await userEvent.upload(input, file("notes.txt"));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /could not be read as an image/,
    );
    expect(onChange).not.toHaveBeenCalled();
  });

  /**
   * The input is cleared on every change so that picking the *same* file again
   * fires `change` again — without it a failed upload could not be retried
   * except by choosing a different file.
   */
  it("clears the input so the same file can be retried", async () => {
    cropToSquarePng.mockRejectedValue(new Error("not an image"));
    const { input } = setup();
    await userEvent.upload(input, file());
    await screen.findByRole("alert");
    expect((input as HTMLInputElement).value).toBe("");

    cropToSquarePng.mockResolvedValue(CROPPED);
    await userEvent.upload(input, file());
    expect(cropToSquarePng).toHaveBeenCalledTimes(2);
  });

  it("offers Remove only once there is an icon, and clears it", async () => {
    expect(screen.queryByRole("button", { name: /Remove/ })).toBeNull();
    const { onChange } = setup(CROPPED);

    expect(screen.getByRole("button", { name: "Replace icon" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Remove/ }));
    expect(onChange).toHaveBeenCalledWith("");
  });

  it("labels the upload button by whether there is already an icon", () => {
    setup();
    expect(screen.getByRole("button", { name: "Upload icon" })).toBeInTheDocument();
  });

  /**
   * The help text is where an operator learns what will actually happen, so it
   * names the size and the wording the button will carry.
   */
  it("says what the icon becomes and where it appears", () => {
    setup();
    const help = screen.getByText(/Cropped to/);
    expect(help).toHaveTextContent(
      `${PROVIDER_ICON_SIZE_PX}×${PROVIDER_ICON_SIZE_PX}`,
    );
    expect(help).toHaveTextContent(/Sign in with Acme SSO/);
  });

  it("falls back to a neutral phrase when the provider is not named yet", () => {
    render(
      <ProviderIconField
        value=""
        onChange={vi.fn()}
        idPrefix="edit"
        displayName="   "
      />,
    );
    expect(screen.getByText(/Sign in with this provider/)).toBeInTheDocument();
  });
});
