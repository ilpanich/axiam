import type { ProviderKind } from "@/services/federation";

/**
 * Identity-provider marks, as inline SVG.
 *
 * # Why these are local rather than fetched
 *
 * `docker/nginx.conf.template` serves the SPA under
 * `default-src 'self'; img-src 'self' data:`. A remote logo URL is therefore
 * blocked — **silently**, with no console error a user would see, leaving a
 * button with a missing image. Inline SVG is the one form that is guaranteed to
 * render, needs no build-time asset pipeline, and inherits the button's colour
 * where the brand permits it.
 *
 * # These are trademarks, and the guidelines are not advisory
 *
 * Each mark below is the provider's published sign-in logo, reproduced without
 * modification. Google, Apple and Microsoft all publish sign-in-button rules
 * covering the mark, the wording, the colours and a minimum size; those rules
 * are implemented in `ProviderSignInButton`, and they are the reason an operator
 * cannot replace these marks with an upload (the server refuses it). The
 * generic kinds have no mark to reproduce, which is exactly why they may carry
 * a custom one.
 */

interface MarkProps {
  /** Rendered edge length in CSS pixels. */
  size?: number;
}

function Google({ size = 18 }: MarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      aria-hidden="true"
      focusable="false"
    >
      <path
        fill="#EA4335"
        d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
      />
      <path
        fill="#4285F4"
        d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
      />
      <path
        fill="#FBBC05"
        d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
      />
      <path
        fill="#34A853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
      />
    </svg>
  );
}

function Microsoft({ size = 18 }: MarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 23 23"
      aria-hidden="true"
      focusable="false"
    >
      <path fill="#F25022" d="M1 1h10v10H1z" />
      <path fill="#7FBA00" d="M12 1h10v10H12z" />
      <path fill="#00A4EF" d="M1 12h10v10H1z" />
      <path fill="#FFB900" d="M12 12h10v10H12z" />
    </svg>
  );
}

/**
 * Apple's mark is monochrome and takes the button's foreground colour, which is
 * what Apple's guidelines require: white on the black button, black on the
 * white one. `currentColor` is how that stays true without a second asset.
 */
function Apple({ size = 18 }: MarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z" />
    </svg>
  );
}

/** GitHub's Octocat mark, monochrome per GitHub's logo guidelines. */
function Github({ size = 18 }: MarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}

/** Facebook's "f" mark, white on the brand blue the button supplies. */
function Facebook({ size = 18 }: MarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" />
    </svg>
  );
}

/**
 * The fallback for a generic provider with no uploaded icon.
 *
 * A key rather than a letter or a coloured circle: it says "identity provider"
 * without implying a brand, and it looks deliberate next to the real marks
 * instead of looking like one that failed to load.
 */
function GenericMark({ size = 18 }: MarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d="m15.5 7.5 3 3L22 7l-3-3" />
      <path d="m19 10-1.5 1.5" />
      <circle cx="8" cy="15" r="6" />
      <path d="m13.5 10.5 4-4" />
    </svg>
  );
}

const BUNDLED: Partial<
  Record<ProviderKind, (p: MarkProps) => React.ReactElement>
> = {
  google: Google,
  microsoft: Microsoft,
  apple: Apple,
  github: Github,
  facebook: Facebook,
};

export interface ProviderMarkProps extends MarkProps {
  kind: ProviderKind;
  /**
   * The operator's uploaded icon for a generic provider, as a `data:` URL.
   *
   * Ignored for a kind that ships its own mark — the server refuses to store
   * one there, and honouring it here would mean the two disagreed about which
   * rule applies.
   */
  buttonIcon?: string | null;
}

/**
 * The mark for a provider: its own where AXIAM ships one, the operator's
 * upload where they provided one, and a neutral glyph otherwise.
 */
export function ProviderMark({ kind, buttonIcon, size = 18 }: ProviderMarkProps) {
  const Bundled = BUNDLED[kind];
  if (Bundled) {
    return <Bundled size={size} />;
  }
  if (buttonIcon) {
    return (
      <img
        src={buttonIcon}
        width={size}
        height={size}
        // Decorative: the button's own text already says which provider this
        // is, so an alt repeating it would be read twice.
        alt=""
        aria-hidden="true"
        className="rounded-sm object-contain"
        style={{ width: size, height: size }}
      />
    );
  }
  return <GenericMark size={size} />;
}
