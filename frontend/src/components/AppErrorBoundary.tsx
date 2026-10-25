import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Last-resort guard for the SPA. The app has no other boundary, so a single
 * render error (observed on /tasks: `filter is not a function`) unmounted the
 * entire tree and left a blank page. This swaps in a recovery card instead —
 * with the CSRF-cookie fix, "Go to overview" is a full reload that keeps the
 * session.
 */
export class AppErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Message and component stack only — never page data (passwords, tokens).
    console.error("CRIX page crashed:", error.message, info.componentStack ?? "");
  }

  render() {
    if (this.state.error) {
      return (
        <div className="grid min-h-screen place-items-center px-4" role="alert">
          <div
            className="glass panel-pad w-full max-w-sm space-y-3 text-center"
            data-testid="app-error-boundary"
          >
            <h1 className="text-lg font-semibold text-ink">This page hit an unexpected error</h1>
            <p className="text-sm text-ink-muted">
              The rest of CRIX is unaffected. Try rendering the page again, or go back to the
              overview. If it keeps happening, include the message below in your report.
            </p>
            <p className="break-all rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-left font-mono text-[11px] text-rose-200">
              {this.state.error.message}
            </p>
            <div className="flex justify-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="primary"
                data-testid="boundary-retry"
                onClick={() => this.setState({ error: null })}
              >
                Try again
              </Button>
              <Button
                type="button"
                size="sm"
                data-testid="boundary-home"
                onClick={() => window.location.assign("/")}
              >
                Go to overview
              </Button>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
