import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle,
  CheckCircle2,
  MessageSquare,
  ShieldAlert,
  X,
} from 'lucide-react';

export interface ThreatToastInput {
  id?: string;
  triggerKey?: string;
  severity: 'high' | 'medium' | 'safe';
  title: string;
  summary: string;
  matchedPattern?: string;
  recommendations: string[];
  actionLabel?: string;
  onAction?: () => void;
  durationMs?: number;
}

interface ThreatToastItem extends ThreatToastInput {
  id: string;
  createdAt: number;
}

interface ToastContextValue {
  pushThreatToast: (toast: ThreatToastInput) => void;
  dismissToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function useThreatToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useThreatToast must be used within a ToastProvider');
  }
  return ctx;
}

interface ToastProviderProps {
  children: ReactNode;
  onOpenSafetyAssistant?: () => void;
}

export function ToastProvider({ children, onOpenSafetyAssistant }: ToastProviderProps) {
  const [toasts, setToasts] = useState<ThreatToastItem[]>([]);
  const [pausedIds, setPausedIds] = useState<Record<string, boolean>>({});
  const recentTriggerMapRef = useRef<Map<string, number>>(new Map());

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const pushThreatToast = useCallback((input: ThreatToastInput) => {
    const now = Date.now();
    if (input.triggerKey) {
      const lastFired = recentTriggerMapRef.current.get(input.triggerKey);
      // Avoid duplicate alerts for the exact same pattern within 15 seconds
      if (lastFired && now - lastFired < 15_000) {
        return;
      }
      recentTriggerMapRef.current.set(input.triggerKey, now);
    }

    const id = input.id || `toast_${now}_${Math.random().toString(36).slice(2, 6)}`;
    const nextItem: ThreatToastItem = {
      ...input,
      id,
      createdAt: now,
    };

    setToasts((prev) => {
      const deduped = input.triggerKey
        ? prev.filter((t) => t.triggerKey !== input.triggerKey)
        : prev;
      // Cap visible alerts at 3 to keep viewport uncluttered
      return [nextItem, ...deduped].slice(0, 3);
    });
  }, []);

  // Auto-dismiss timer that pauses when the user hovers/focuses a toast
  useEffect(() => {
    if (toasts.length === 0) return;

    const timer = window.setInterval(() => {
      const now = Date.now();
      setToasts((prev) =>
        prev.filter((item) => {
          if (pausedIds[item.id]) return true;
          const ttl = item.durationMs ?? (item.severity === 'high' ? 14_000 : 10_000);
          return now - item.createdAt < ttl;
        })
      );
    }, 500);

    return () => window.clearInterval(timer);
  }, [toasts.length, pausedIds]);

  return (
    <ToastContext.Provider value={{ pushThreatToast, dismissToast }}>
      {children}

      {/* Accessible Real-Time Security Toast Stack */}
      <div
        aria-live="assertive"
        aria-label="Real-time security notifications"
        className="pointer-events-none fixed top-20 right-4 left-4 sm:left-auto sm:w-[420px] z-50 flex flex-col gap-3"
      >
        <AnimatePresence initial={false}>
          {toasts.map((toast) => {
            const isHigh = toast.severity === 'high';
            const isMedium = toast.severity === 'medium';

            const borderStyle = isHigh
              ? 'border-red-300 bg-white'
              : isMedium
              ? 'border-amber-300 bg-white'
              : 'border-emerald-300 bg-white';

            const headerBg = isHigh
              ? 'bg-red-50 border-b border-red-200'
              : isMedium
              ? 'bg-amber-50 border-b border-amber-200'
              : 'bg-emerald-50 border-b border-emerald-200';

            const labelText = isHigh
              ? 'High-Risk Alert'
              : isMedium
              ? 'Caution Alert'
              : 'Safety Verified';

            const labelColor = isHigh
              ? 'text-red-800'
              : isMedium
              ? 'text-amber-900'
              : 'text-emerald-900';

            const Icon = isHigh
              ? ShieldAlert
              : isMedium
              ? AlertTriangle
              : CheckCircle2;

            const iconColor = isHigh
              ? 'text-red-600'
              : isMedium
              ? 'text-amber-600'
              : 'text-emerald-600';

            return (
              <motion.div
                key={toast.id}
                role="alert"
                initial={{ opacity: 0, y: -12, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -10, scale: 0.98 }}
                transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
                onMouseEnter={() =>
                  setPausedIds((prev) => ({ ...prev, [toast.id]: true }))
                }
                onMouseLeave={() =>
                  setPausedIds((prev) => ({ ...prev, [toast.id]: false }))
                }
                className={`pointer-events-auto overflow-hidden rounded-2xl border shadow-xl ${borderStyle}`}
              >
                {/* Header strip */}
                <div className={`px-4 py-2.5 flex items-center justify-between gap-2 ${headerBg}`}>
                  <div className="flex items-center gap-2 text-xs">
                    <Icon className={`h-4 w-4 shrink-0 ${iconColor}`} />
                    <span className={`font-bold ${labelColor}`}>{labelText}</span>
                    <span className="text-slate-500 font-medium">Instant Guard</span>
                  </div>
                  <button
                    type="button"
                    aria-label="Dismiss security alert"
                    onClick={() => dismissToast(toast.id)}
                    className="rounded-lg p-1 text-slate-500 hover:bg-white/80 hover:text-slate-900 min-h-[32px] min-w-[32px] flex items-center justify-center cursor-pointer"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>

                {/* Body & Immediate Recommendations */}
                <div className="p-4 space-y-3">
                  <div className="space-y-1">
                    <h3 className="text-sm font-bold text-slate-900 leading-snug">
                      {toast.title}
                    </h3>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      {toast.summary}
                    </p>
                    {toast.matchedPattern && (
                      <p className="font-mono text-[11px] text-slate-800 bg-slate-100 rounded-md px-2.5 py-1 inline-block break-all mt-1">
                        Flagged: {toast.matchedPattern}
                      </p>
                    )}
                  </div>

                  {toast.recommendations.length > 0 && (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-1.5">
                      <div className="text-[11px] font-bold text-slate-700">
                        Immediate Safety Steps
                      </div>
                      <ul className="space-y-1 text-xs text-slate-700">
                        {toast.recommendations.slice(0, 3).map((rec, i) => (
                          <li key={i} className="flex items-start gap-2">
                            <span className="font-mono font-bold text-slate-500">
                              {i + 1}.
                            </span>
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5">
                    <div className="flex items-center gap-2">
                      {toast.onAction && toast.actionLabel && (
                        <button
                          type="button"
                          onClick={() => {
                            toast.onAction?.();
                            dismissToast(toast.id);
                          }}
                          className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 min-h-[36px] cursor-pointer"
                        >
                          {toast.actionLabel}
                        </button>
                      )}
                      {onOpenSafetyAssistant && isHigh && (
                        <button
                          type="button"
                          onClick={() => {
                            onOpenSafetyAssistant();
                            dismissToast(toast.id);
                          }}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 min-h-[36px] cursor-pointer"
                        >
                          <MessageSquare className="h-3.5 w-3.5" />
                          Ask Assistant
                        </button>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={() => dismissToast(toast.id)}
                      className="text-xs font-medium text-slate-500 hover:text-slate-800 px-2 py-1 cursor-pointer"
                    >
                      Dismiss
                    </button>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}
