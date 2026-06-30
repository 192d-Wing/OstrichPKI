import { config } from "@/lib/config";

// Classification banner shown at the top and bottom of every page (NPE portal
// requirements §3). The background color follows the DoD/IC standard palette and
// is derived from the banner TEXT, so an operator reconfigures it by setting
// `classificationBanner` in the deployment config (configmap). An explicit
// `classificationColor` overrides the derived color for non-standard banners.
//
//   CUI ................. purple
//   CONFIDENTIAL ........ blue
//   SECRET .............. red
//   TOP SECRET .......... orange
//   TOP SECRET//SCI ..... yellow
//   UNCLASSIFIED ........ green

interface BannerStyle {
  background: string;
  color: string;
}

// Ordered most-specific first; the first matching rule wins.
const STANDARD: ReadonlyArray<{
  test: (upper: string) => boolean;
  background: string;
  color: string;
}> = [
  // TOP SECRET//SCI (any SCI compartment under Top Secret) -> yellow, black text.
  {
    test: (t) => t.includes("TOP SECRET") && t.includes("SCI"),
    background: "#fce100",
    color: "#000000",
  },
  // TOP SECRET -> orange, black text.
  {
    test: (t) => t.includes("TOP SECRET"),
    background: "#ff8c00",
    color: "#000000",
  },
  // SECRET -> red.
  { test: (t) => t.includes("SECRET"), background: "#c8102e", color: "#ffffff" },
  // CONFIDENTIAL -> blue.
  {
    test: (t) => t.includes("CONFIDENTIAL"),
    background: "#0033a0",
    color: "#ffffff",
  },
  // CUI / Controlled Unclassified Information -> purple.
  {
    test: (t) => t.includes("CUI") || t.includes("CONTROLLED"),
    background: "#502b85",
    color: "#ffffff",
  },
  // UNCLASSIFIED -> green.
  {
    test: (t) => t.includes("UNCLASSIFIED") || t.includes("UNCLAS"),
    background: "#007a33",
    color: "#ffffff",
  },
];

// Pick a readable foreground (black/white) for an explicit hex override; defaults
// to white for non-hex CSS colors.
function readableForeground(background: string): string {
  const hex = /^#?([0-9a-f]{6})$/i.exec(background.trim());
  if (!hex) return "#ffffff";
  const n = Number.parseInt(hex[1], 16);
  const r = (n >> 16) & 0xff;
  const g = (n >> 8) & 0xff;
  const b = n & 0xff;
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance > 0.6 ? "#000000" : "#ffffff";
}

function bannerStyle(text: string, override?: string | null): BannerStyle {
  if (override) {
    return { background: override, color: readableForeground(override) };
  }
  const upper = text.toUpperCase();
  const match = STANDARD.find((rule) => rule.test(upper));
  // Fail safe: an unrecognized banner is shown as SECRET red (high visibility),
  // never silently green.
  return match ?? { background: "#c8102e", color: "#ffffff" };
}

export function ClassificationBanner() {
  const text = config.classificationBanner;
  const { background, color } = bannerStyle(text, config.classificationColor);

  return (
    <div
      style={{
        background,
        color,
        textAlign: "center",
        fontWeight: 700,
        fontSize: "0.8rem",
        padding: "2px 0",
        letterSpacing: "0.05em",
      }}
      aria-label="Classification banner"
    >
      {text}
    </div>
  );
}
