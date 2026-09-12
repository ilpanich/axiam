import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { UserSessionsDialog } from "@/components/UserSessionsDialog";
import { renderWithProviders } from "@/test/renderWithProviders";
import type { UserSession } from "@/services/users";

/**
 * T-254 — the admin view of the refresh-replay marker.
 *
 * The property under test is the one the decision actually asks for: an
 * operator must be able to tell a FAPI grace retry from a refused replay *at a
 * glance*, so the two must not render as the same badge with a different
 * number in it.
 */
function mkSession(over: Partial<UserSession> = {}): UserSession {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    created_at: "2026-09-12T10:00:00Z",
    expires_at: "2026-09-12T11:00:00Z",
    authenticated_at: "2026-09-12T09:00:00Z",
    amr: ["pwd", "otp", "mfa"],
    ip_address: "203.0.113.7",
    user_agent: null,
    refresh_replay_verdict: "none",
    refresh_replay_at: null,
    refresh_replay_grace_accepted: 0,
    refresh_replay_refused: 0,
    ...over,
  };
}

beforeEach(() => vi.clearAllMocks());

describe("UserSessionsDialog", () => {
  it("renders nothing when closed, and asks for nothing", () => {
    const { container } = renderWithProviders(
      <UserSessionsDialog open={false} onClose={() => {}} userId="u1" username="ada" />
    );
    expect(container.firstChild).toBeNull();
    expect(apiMock.get).not.toHaveBeenCalled();
  });

  it("shows an untroubled session with no badge at all", async () => {
    apiMock.get.mockResolvedValueOnce(res([mkSession()]));
    renderWithProviders(
      <UserSessionsDialog open onClose={() => {}} userId="u1" username="ada" />
    );
    await waitFor(() =>
      expect(apiMock.get).toHaveBeenCalledWith("/api/v1/users/u1/sessions")
    );
    expect(await screen.findByText(/pwd, otp, mfa/)).toBeInTheDocument();
    expect(screen.queryByText(/FAPI grace retry/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Replay refused/)).not.toBeInTheDocument();
  });

  it("labels an accepted FAPI grace retry as the retry the window exists for", async () => {
    apiMock.get.mockResolvedValueOnce(
      res([
        mkSession({
          refresh_replay_verdict: "fapi_grace_retry",
          refresh_replay_grace_accepted: 2,
          refresh_replay_at: "2026-09-12T10:30:00Z",
        }),
      ])
    );
    renderWithProviders(
      <UserSessionsDialog open onClose={() => {}} userId="u1" username="ada" />
    );
    expect(await screen.findByText(/FAPI grace retry ×2/)).toBeInTheDocument();
    // …and emphatically not as an incident: no alert banner.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("raises a refused replay as an incident, naming the audit action to search", async () => {
    apiMock.get.mockResolvedValueOnce(
      res([
        mkSession({
          refresh_replay_verdict: "refused",
          refresh_replay_grace_accepted: 0,
          refresh_replay_refused: 1,
          refresh_replay_at: "2026-09-12T10:30:00Z",
        }),
      ])
    );
    renderWithProviders(
      <UserSessionsDialog open onClose={() => {}} userId="u1" username="ada" />
    );
    expect(await screen.findByText(/Replay refused/)).toBeInTheDocument();
    const banner = screen.getByRole("alert");
    expect(banner).toHaveTextContent(/One session has/);
    expect(banner).toHaveTextContent("oauth2.refresh_token_replayed");
  });

  it("a refusal outranks accepted retries in the same list", async () => {
    apiMock.get.mockResolvedValueOnce(
      res([
        mkSession({
          id: "aaaaaaaa-0000-0000-0000-000000000001",
          refresh_replay_verdict: "fapi_grace_retry",
          refresh_replay_grace_accepted: 5,
        }),
        mkSession({
          id: "aaaaaaaa-0000-0000-0000-000000000002",
          refresh_replay_verdict: "refused",
          refresh_replay_refused: 1,
        }),
      ])
    );
    renderWithProviders(
      <UserSessionsDialog open onClose={() => {}} userId="u1" username="ada" />
    );
    expect(await screen.findByText(/FAPI grace retry ×5/)).toBeInTheDocument();
    expect(screen.getByText(/Replay refused/)).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(/One session has/);
  });

  it("says so plainly when the user holds no sessions", async () => {
    apiMock.get.mockResolvedValueOnce(res([]));
    renderWithProviders(
      <UserSessionsDialog open onClose={() => {}} userId="u1" username="ada" />
    );
    expect(await screen.findByText(/holds no sessions/i)).toBeInTheDocument();
  });
});
