import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { applyTheme, readThemePreference } from "./app/theme";
import { currentWindowLabel } from "./lib/api";
import { CardCodePrompt } from "./pages/CardCodePrompt";
import { UnlockPrompt } from "./pages/UnlockPrompt";
import "./styles.css";

// public/theme-init.js already ran; apply again in case it was blocked.
applyTheme(readThemePreference());

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {{ unlock: <UnlockPrompt />, "card-code": <CardCodePrompt /> }[currentWindowLabel()] ?? <App />}
  </StrictMode>
);
