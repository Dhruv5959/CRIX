import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity,
  BarChart3,
  Box,
  ClipboardList,
  GitBranch,
  History,
  LayoutDashboard,
  ListChecks,
  Menu,
  Network,
  Route,
  ScrollText,
  Shield,
  ShieldHalf,
  Sparkles,
  Users,
  X,
} from "lucide-react";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Health } from "@/lib/types";

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ size?: number }>;
  end?: boolean;
  /** Only show for these roles. Omit = visible to all. */
  roles?: string[];
}

const nav: NavItem[] = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/assets", label: "Assets", icon: Box },
  { to: "/members", label: "Members", icon: Users },
  { to: "/signals", label: "Connected Signals", icon: ClipboardList },
  { to: "/propagation", label: "Propagation", icon: Route },
  { to: "/correlations", label: "Correlations", icon: GitBranch },
  { to: "/risk", label: "Risk & Attribution", icon: Activity },
  { to: "/risk-history", label: "Risk History", icon: History },
  { to: "/graph", label: "Dependency Graph", icon: Network },
  { to: "/tasks", label: "Tasks", icon: ListChecks },
  { to: "/remediation", label: "Remediation & What-If", icon: ListChecks },
  { to: "/explanation", label: "GraphRAG Explanation", icon: Sparkles },
  { to: "/evaluation", label: "Evaluation", icon: BarChart3 },
  { to: "/knowledge", label: "Knowledge Graph", icon: ScrollText },
  { to: "/audit", label: "Audit & RBAC", icon: Shield, roles: ["ORG_ADMIN"] },
];

export default function Layout() {
  const { user, org, role, logout } = useAuth();
  const navigate = useNavigate();
  const [health, setHealth] = useState<Health | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  // Close the mobile drawer on Escape (the overlay click and every nav link
  // also close it).
  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenuOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menuOpen]);

  // Which breach provider the backend will use, so the sidebar states the
  // capability honestly instead of only mentioning HIBP's API key.
  const breachLookupAvailable =
    !!health && (health.breach_email_provider === "xposedornot" || health.hibp_configured);
  const shortProviderLabel = (health?.breach_email_provider_label || "").replace(
    /\s*\(.*\)\s*$/,
    "",
  );
  const breachLookupLabel = !health
    ? ""
    : health.breach_email_provider === "hibp"
      ? `Breach lookup: HIBP ${health.hibp_configured ? "configured" : "not configured"}`
      : `Breach lookup: ${shortProviderLabel || health.breach_email_provider}`;

  // Filter nav by role
  const visibleNav = nav.filter((item) => {
    if (!item.roles) return true;
    return role && item.roles.includes(role);
  });

  const brand = (
    <div className="flex items-center gap-2.5">
      <span className="grid h-9 w-9 place-items-center rounded-xl border border-accent/25 bg-accent/15 text-accent shadow-accent backdrop-blur-md">
        <ShieldHalf size={18} />
      </span>
      <div>
        <div className="text-sm font-semibold tracking-wide text-ink">CRIX</div>
        <div className="text-[10px] uppercase tracking-[0.16em] text-ink-faint">
          Contextual Risk
        </div>
      </div>
    </div>
  );

  const sidebarBody = (
    <>
      <div className="flex items-center justify-between px-5 py-5">
        {brand}
        <button
          type="button"
          aria-label="Close navigation"
          onClick={() => setMenuOpen(false)}
          className="cursor-pointer rounded-md p-1.5 text-ink-faint hover:bg-white/10 hover:text-ink lg:hidden"
        >
          <X size={18} />
        </button>
      </div>

      <nav aria-label="Primary" className="flex-1 space-y-1 overflow-y-auto px-3 py-2">
        {visibleNav.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={() => setMenuOpen(false)}
            className={({ isActive }) =>
              cn(
                "relative flex items-center gap-2.5 rounded-xl border border-transparent px-3 py-2 text-sm transition-colors",
                isActive
                  ? "border-accent/25 bg-accent/[0.14] text-accent"
                  : "text-ink-muted hover:border-white/10 hover:bg-white/10 hover:text-ink",
              )
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-full bg-accent" />
                )}
                <Icon size={16} />
                {label}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-white/10 p-4">
        <div className="mb-3 text-xs text-ink-faint">
          <div className="truncate text-ink-muted">{user?.email}</div>
          {org && (
            <div className="mt-0.5 text-[10px] text-ink-faint">
              {org.name} · {role}
            </div>
          )}
          <div className="mt-1 space-y-0.5">
            {health ? (
              <>
                <span
                  className={cn(
                    "inline-flex items-center gap-1",
                    breachLookupAvailable ? "text-emerald-300" : "text-amber-300",
                  )}
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-current" />
                  {breachLookupLabel}
                </span>
                <span className="inline-flex items-center gap-1 text-emerald-300">
                  <span className="h-1.5 w-1.5 rounded-full bg-current" />
                  Password range: HIBP (keyless)
                </span>
              </>
            ) : (
              <span className="text-ink-faint">API offline</span>
            )}
          </div>
        </div>
        <Button
          variant="secondary"
          size="sm"
          className="w-full"
          onClick={() => logout().then(() => navigate("/login"))}
        >
          Sign out
        </Button>
      </div>
    </>
  );

  return (
    <div className="flex min-h-screen">
      {/* Desktop / tablet-landscape sidebar */}
      <aside className="glass-chrome hidden w-64 shrink-0 flex-col border-r border-white/10 lg:flex">
        {sidebarBody}
      </aside>

      {/* Mobile / tablet drawer */}
      {menuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div
            className="absolute inset-0 bg-black/50 backdrop-blur-sm"
            onClick={() => setMenuOpen(false)}
            aria-hidden="true"
          />
          <aside className="glass-chrome absolute left-0 top-0 flex h-full w-64 max-w-[80vw] flex-col border-r border-white/10 shadow-glass">
            {sidebarBody}
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Mobile top bar */}
        <header className="glass-chrome sticky top-0 z-30 flex items-center gap-3 border-b border-white/10 px-4 py-3 lg:hidden">
          <button
            type="button"
            aria-label="Open navigation"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen(true)}
            className="cursor-pointer rounded-md p-1.5 text-ink-muted hover:bg-white/10 hover:text-ink"
          >
            <Menu size={20} />
          </button>
          {brand}
        </header>

        <main className="flex-1 overflow-x-hidden">
          <div className="mx-auto max-w-[1200px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
