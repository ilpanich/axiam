import { RouterProvider } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { useAuthInit } from "@/hooks/useAuthInit";
import { useAuthStore } from "@/stores/auth";
import { Loader2 } from "lucide-react";
import { router } from "./router";
import { queryClient } from "@/lib/queryClient";
import { Toaster } from "@/components/Toaster";

// Public routes registered in `./router`:
//   - /login               — sign-in flow
//   - /bootstrap           — first-run admin setup (Phase 03-05)
//   - /auth/forgot-password, /auth/reset-password, /auth/verify-email

function AuthGate({ children }: { children: React.ReactNode }) {
  useAuthInit();
  const isInitializing = useAuthStore((s) => s.isInitializing);

  if (isInitializing) {
    return (
      <div
        className="flex min-h-screen items-center justify-center bg-axiam-gradient"
        aria-live="polite"
      >
        <Loader2 className="h-6 w-6 animate-spin text-primary" />
      </div>
    );
  }

  return <>{children}</>;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthGate>
        <RouterProvider router={router} />
      </AuthGate>
      <Toaster />
    </QueryClientProvider>
  );
}

export default App;
