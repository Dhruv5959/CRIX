// Auth context: holds the current user + org membership, attempts a silent
// refresh on load (using the httpOnly cookie), and exposes login/register/logout.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, setTokens } from "./api";
import type { OrgInfo, OrgRole, User } from "./types";

interface AuthState {
  user: User | null;
  org: OrgInfo | null;
  role: OrgRole | null;
  loading: boolean;
  login: (email: string, password: string, totp?: string) => Promise<void>;
  register: (email: string, password: string, breachMonitorConsent?: boolean) => Promise<void>;
  logout: () => Promise<void>;
  refreshOrg: () => Promise<void>;
  /** Re-read /me so Feature A/B outcome metadata stays fresh after actions. */
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [org, setOrg] = useState<OrgInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const loadOrg = useCallback(async () => {
    try {
      const orgInfo = await api.getOrg();
      setOrg(orgInfo);
    } catch {
      setOrg(null);
    }
  }, []);

  useEffect(() => {
    // Try a silent refresh so a page reload keeps the session.
    (async () => {
      try {
        await api.refresh();
        const me = await api.me();
        setUser(me);
        await loadOrg();
      } catch {
        setTokens(null, null);
      } finally {
        setLoading(false);
      }
    })();
  }, [loadOrg]);

  const login = useCallback(async (email: string, password: string, totp?: string) => {
    await api.login(email, password, totp);
    const me = await api.me();
    setUser(me);
    await loadOrg();
  }, [loadOrg]);

  const register = useCallback(async (email: string, password: string, breachMonitorConsent = false) => {
    await api.register(email, password, breachMonitorConsent);
    await api.login(email, password);
    const me = await api.me();
    setUser(me);
    await loadOrg();
  }, [loadOrg]);

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
    setOrg(null);
  }, []);

  const refreshUser = useCallback(async () => {
    try {
      setUser(await api.me());
    } catch {
      // Keep the current user state on a transient failure; nothing rewrites
      // it with a guess.
    }
  }, []);

  const role = org?.role ?? null;

  const value = useMemo(
    () => ({ user, org, role, loading, login, register, logout, refreshOrg: loadOrg, refreshUser }),
    [user, org, role, loading, login, register, logout, loadOrg, refreshUser],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
