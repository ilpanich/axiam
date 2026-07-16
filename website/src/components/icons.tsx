/** Inline SVG icons used across the AXIAM website. */

export function GithubIcon({ size = 17 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.6-1.4-1.3-1.8-1.3-1.8-1.1-.7 0-.7 0-.7 1.2 0 1.9 1.2 1.9 1.2 1 1.8 2.8 1.3 3.5 1 0-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-5.9 0-1.3.5-2.4 1.2-3.2 0-.3-.5-1.5.2-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.7 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .3" />
    </svg>
  );
}

const strokeProps = {
  width: 24,
  height: 24,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.8,
} as const;

export function ShieldIcon() {
  return (
    <svg {...strokeProps}>
      <path d="M12 3 4 6v5c0 4.5 3.2 8.3 8 9.5 4.8-1.2 8-5 8-9.5V6l-8-3Z" />
    </svg>
  );
}

export function KeyholeIcon() {
  return (
    <svg {...strokeProps}>
      <circle cx="8" cy="12" r="4" />
      <path d="M12 12h9M18 12v4M15 12v3" />
    </svg>
  );
}

export function LockIcon() {
  return (
    <svg {...strokeProps}>
      <path d="M7 11V8a5 5 0 0 1 10 0v3" />
      <rect x="5" y="11" width="14" height="9" rx="2" />
    </svg>
  );
}

export function NodesIcon() {
  return (
    <svg {...strokeProps}>
      <circle cx="13" cy="6" r="2.4" />
      <circle cx="6" cy="18" r="2.4" />
      <circle cx="20" cy="18" r="2.4" />
      <path d="M13 8.4v3M13 11.4 7 16M13 11.4 19 16" />
    </svg>
  );
}

export function ListIcon() {
  return (
    <svg {...strokeProps}>
      <path d="M4 6h16M4 12h16M4 18h10" />
    </svg>
  );
}

export function LayersIcon() {
  return (
    <svg {...strokeProps}>
      <path d="M4 7l8-4 8 4-8 4-8-4Z" />
      <path d="M4 12l8 4 8-4M4 17l8 4 8-4" />
    </svg>
  );
}
