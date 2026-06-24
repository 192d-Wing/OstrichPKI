import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import "@cloudscape-design/global-styles/index.css";
import App from "@/App";
import { ThemeProvider } from "@/components/theme-provider";
import { config } from "@/lib/config";
import "@/index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <BrowserRouter basename={config.basename}>
        <App />
      </BrowserRouter>
    </ThemeProvider>
  </StrictMode>,
);
