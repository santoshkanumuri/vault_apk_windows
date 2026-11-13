import { ConfirmProvider } from "./app/confirm";
import { useEffect } from "react";
import { RouterProvider, useRouter } from "./app/router";
import { PreferencesProvider } from "./app/settings";
import { Shell } from "./app/Shell";
import { ThemeProvider } from "./app/theme";
import { ToastProvider } from "./app/toast";
import { useVault, VaultProvider } from "./app/vault";
import { SplashScreen, UnlockPage } from "./pages/Unlock";

function Gate() {
  const { ready, unlocked } = useVault();
  const { reset } = useRouter();
  // Forget history, scroll positions, and filters whenever the vault closes.
  useEffect(() => { if (!unlocked) reset(); }, [unlocked, reset]);
  if (!ready) return <SplashScreen />;
  return unlocked ? <Shell /> : <UnlockPage />;
}

export default function App() {
  return (
    <ThemeProvider>
      <PreferencesProvider>
        <ToastProvider>
          <ConfirmProvider>
            <VaultProvider>
              <RouterProvider>
                <Gate />
              </RouterProvider>
            </VaultProvider>
          </ConfirmProvider>
        </ToastProvider>
      </PreferencesProvider>
    </ThemeProvider>
  );
}
