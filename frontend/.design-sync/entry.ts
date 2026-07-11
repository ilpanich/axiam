// Barrel entry for the design-sync bundle. The app has no library build, so this
// is the "dist entry" the converter bundles into window.AxiamUI. It re-exports
// the real components from src/ — nothing is reimplemented here.
export * from "../src/components/ui/button";
export * from "../src/components/ui/badge";
export * from "../src/components/ui/card";
export * from "../src/components/ui/input";
export * from "../src/components/ui/label";
export * from "../src/components/ui/textarea";

export * from "../src/components/shared";
export * from "../src/components/ConfirmDialog";
export * from "../src/components/DataTable";
export * from "../src/components/ForbiddenPage";
export * from "../src/components/FormDialog";
export * from "../src/components/PageHeader";
export * from "../src/components/PasswordPolicyChecker";
export * from "../src/components/SearchInput";
export * from "../src/components/SecretRevealModal";
export * from "../src/components/StatusBadge";
export * from "../src/components/Toaster";
export * from "../src/components/UserSearchDialog";
export * from "../src/components/ResourceTree";

export * from "../src/components/layout/AppLayout";
export * from "../src/components/layout/PublicLayout";
export * from "../src/components/layout/Sidebar";
export * from "../src/components/layout/Topbar";

export * from "../src/components/auth/TotpSetupPanel";
