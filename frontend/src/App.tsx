import { RouterProvider } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useAuthInit } from "@/hooks/useAuthInit";
import { useAuthStore } from "@/stores/auth";
import { Loader2 } from "lucide-react";
import { router } from "./router";

// Public routes registered in `./router`:
//   - /login               — sign-in flow
//   - /bootstrap           — first-run admin setup (Phase 03-05)
//   - /auth/forgot-password, /auth/reset-password, /auth/verify-email

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      retry: (failureCount, error: unknown) => {
        const status = (error as { response?: { status?: number } })?.response
          ?.status;
        if (status === 401 || status === 403) return false;
        return failureCount < 2;
      },
    },
  },
});

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
    </QueryClientProvider>
  );
}

export default App;
