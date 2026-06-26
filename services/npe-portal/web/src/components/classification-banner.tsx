import { config } from "@/lib/config";

// Classification banner shown at the top and bottom of every page (NPE portal
// requirements §3). Color follows DoD convention: green for UNCLASSIFIED/CUI; callers
// deploying at higher classifications override the banner text in config.
export function ClassificationBanner() {
  const text = config.classificationBanner;
  const upper = text.toUpperCase();
  const background = upper.startsWith("CUI") || upper.startsWith("UNCLASSIFIED")
    ? "#006b00"
    : "#c8102e";

  return (
    <div
      style={{
        background,
        color: "#ffffff",
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
