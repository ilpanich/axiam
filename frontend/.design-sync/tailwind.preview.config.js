// Tailwind config used ONLY to compile the design-sync stylesheet
// (.design-sync/compiled.css → cfg.cssEntry → ds-bundle/_ds_bundle.css).
//
// It reuses the app's real theme so cards render with the true AXIAM tokens, and
// widens `content` to include the authored preview cards.
//
// The SAFELIST is load-bearing. Tailwind only emits classes it can see, and the
// app's own source uses a fraction of the theme. But this stylesheet is what every
// design the claude.ai/design agent builds will render against — and that agent
// writes its OWN layout glue (flex, gap-4, p-6, grid-cols-3, …) plus AXIAM tokens
// the app happens not to use yet (bg-card, bg-muted, shadow-glow-purple, …).
// Without the safelist those classes simply do not exist in the shipped CSS and the
// agent's designs render unstyled, silently. So we ship the AXIAM design vocabulary
// in full, plus a bounded set of layout/typography utilities.
import base from "../tailwind.config.js";

// Every colour in the AXIAM theme (see tailwind.config.js `extend.colors`).
const COLORS =
  "background|foreground|surface|border|input|ring|" +
  "primary|accent|muted|destructive|warning|card|popover|secondary";

export default {
  ...base,
  content: ["./src/**/*.{ts,tsx}", "./.design-sync/previews/**/*.tsx"],
  safelist: [
    // ── AXIAM component classes (src/index.css @layer components). These are
    //    purged when src/ doesn't use them, but they ARE the brand look.
    "glass-card",
    "glow-cyan",
    "glow-cyan-lg",
    "glow-purple",
    "sidebar-item-active",
    "btn-primary",
    "input-axiam",
    "bg-axiam-gradient",

    // ── Brand shadows + motion
    { pattern: /^shadow-(glow-cyan|glow-cyan-lg|glow-purple|glass)$/, variants: ["hover", "focus"] },
    { pattern: /^animate-(neon-pulse|ring-spin|ring-spin-reverse|accordion-down|accordion-up|pulse|spin)$/ },

    // ── The token colours, across the properties that carry the design language.
    {
      pattern: new RegExp(`^(bg|text|border|ring|from|to)-(${COLORS})(-foreground)?$`),
      variants: ["hover", "focus-visible", "disabled"],
    },
    // Token colours at an opacity (bg-primary/10, border-primary/30, …) — the
    // idiom AXIAM uses constantly for its translucent glass surfaces.
    {
      pattern: new RegExp(`^(bg|text|border|ring)-(${COLORS})(-foreground)?\\/(5|10|15|20|30|40|50|60|80)$`),
      variants: ["hover"],
    },
    // White/black translucency (bg-white/5 is the glass idiom).
    { pattern: /^(bg|border|text)-(white|black|transparent)(\/(5|10|15|20|30|40|50|60|80))?$/, variants: ["hover"] },

    // ── Layout / spacing / sizing — the agent's own glue.
    { pattern: /^(p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr|gap|gap-x|gap-y|space-x|space-y)-(0|0\.5|1|1\.5|2|2\.5|3|3\.5|4|5|6|7|8|9|10|11|12|14|16|20|24|px|auto)$/ },
    { pattern: /^(w|h|min-w|min-h|max-w|max-h)-(0|1|2|3|4|5|6|8|10|12|16|20|24|32|40|48|56|64|80|96|full|screen|auto|fit|min|max)$/ },
    { pattern: /^max-w-(xs|sm|md|lg|xl|2xl|3xl|4xl|5xl|6xl|7xl|none|prose)$/ },
    { pattern: /^(w|h)-(1\/2|1\/3|2\/3|1\/4|3\/4)$/ },
    { pattern: /^(flex|inline-flex|grid|inline-grid|block|inline-block|inline|hidden|contents)$/ },
    { pattern: /^flex-(row|row-reverse|col|col-reverse|wrap|nowrap|1|auto|initial|none|shrink|grow)$/ },
    { pattern: /^(shrink|grow|basis)-(0|1|auto|full)$/ },
    { pattern: /^(items|justify|content|self|place-items|place-content)-(start|end|center|between|around|evenly|stretch|baseline)$/ },
    { pattern: /^grid-cols-(1|2|3|4|5|6|8|12|none)$/ },
    { pattern: /^(col|row)-span-(1|2|3|4|5|6|full)$/ },
    { pattern: /^(relative|absolute|fixed|sticky|static)$/ },
    { pattern: /^(top|right|bottom|left|inset|inset-x|inset-y)-(0|1|2|4|auto|full)$/ },
    { pattern: /^z-(0|10|20|30|40|50|auto)$/ },
    { pattern: /^overflow-(auto|hidden|visible|scroll|x-auto|y-auto|x-hidden|y-hidden)$/ },

    // ── Typography
    { pattern: /^text-(xs|sm|base|lg|xl|2xl|3xl|4xl|5xl)$/ },
    { pattern: /^font-(sans|mono|normal|medium|semibold|bold)$/ },
    { pattern: /^(uppercase|lowercase|capitalize|normal-case|italic|underline|truncate|whitespace-nowrap|break-words)$/ },
    { pattern: /^(tracking|leading)-(tighter|tight|normal|wide|wider|widest|none|snug|relaxed|loose)$/ },
    { pattern: /^text-(left|center|right|justify)$/ },

    // ── Borders / radius / effects
    { pattern: /^rounded(-none|-sm|-md|-lg|-xl|-2xl|-3xl|-full)?$/ },
    { pattern: /^border(-0|-2|-4|-8|-t|-b|-l|-r)?$/ },
    { pattern: /^opacity-(0|5|10|20|25|30|40|50|60|70|75|80|90|100)$/, variants: ["hover", "disabled", "group-hover"] },
    { pattern: /^(backdrop-blur|blur)(-sm|-md|-lg|-xl)?$/ },
    { pattern: /^(cursor-pointer|cursor-not-allowed|select-none|pointer-events-none|transition-all|transition-colors|transition-opacity|duration-200|ease-in-out)$/ },
  ],
};
