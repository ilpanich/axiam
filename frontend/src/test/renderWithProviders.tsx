import { type ReactElement, type ReactNode } from "react";
import { render, type RenderOptions } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

// A fresh QueryClient per render keeps caches isolated between tests, and we
// disable retries so a rejected query settles immediately.
export function makeClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
}

interface Options extends Omit<RenderOptions, "wrapper"> {
  route?: string;
  routerEntries?: string[];
  client?: QueryClient;
}

/** Render a component wrapped in QueryClientProvider + MemoryRouter. */
export function renderWithProviders(ui: ReactElement, options: Options = {}) {
  const { routerEntries, route = "/", client = makeClient(), ...rest } = options;
  const entries = routerEntries ?? [route];
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={entries}>{children}</MemoryRouter>
      </QueryClientProvider>
    );
  }
  return { client, ...render(ui, { wrapper: Wrapper, ...rest }) };
}
