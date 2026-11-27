import { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Download,
  ExternalLink,
  Globe,
  ListChecks,
  Lock,
  LockOpen,
  MessageSquare,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  X,
  XCircle,
} from 'lucide-react';
import type { ScanResult } from '../types/scam';
import { buildContextualChecklist } from '../utils/securityChecklist';
import { HighlightedText } from './HighlightedText';
import { useThreatToast } from './ToastProvider';

interface ScanResultViewProps {
  result: ScanResult;
  onAskAssistant: (scan: ScanResult) => void;
  onScanAnother: () => void;
}

export function ScanResultView({ result, onAskAssistant, onScanAnother }: ScanResultViewProps) {
  const [checkedSteps, setCheckedSteps] = useState<Record<number, boolean>>({});
  const [showTechnicalUrl, setShowTechnicalUrl] = useState(false);
  const [checklistOpen, setChecklistOpen] = useState(false);
  const { pushThreatToast } = useThreatToast();

  const contextualTasks = useMemo(() => buildContextualChecklist(result), [result]);
  const storageKey = `scamshield_checklist_${result.id}`;

  const [completedTasks, setCompletedTasks] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem(storageKey);
      return saved ? (JSON.parse(saved) as Record<string, boolean>) : {};
    } catch {
      return {};
    }
  });

  useEffect(() => {
    try {
      const saved = localStorage.getItem(storageKey);
      setCompletedTasks(saved ? (JSON.parse(saved) as Record<string, boolean>) : {});
    } catch {
      setCompletedTasks({});
    }
  }, [storageKey]);

  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(completedTasks));
    } catch {
      // Ignore storage quota errors
    }
  }, [storageKey, completedTasks]);

  useEffect(() => {
    if (!checklistOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setChecklistOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [checklistOpen]);

  const toggleChecklistTask = (taskId: string) => {
    setCompletedTasks((prev) => ({ ...prev, [taskId]: !prev[taskId] }));
  };

  const completedTaskCount = contextualTasks.filter((t) => Boolean(completedTasks[t.id])).length;

  const handleProtectedUrlVisit = () => {
    if (!result.urlAnalysis) return;
    const isDangerous =
      result.riskLevel === 'High' ||
      result.riskLevel === 'Medium' ||
      result.urlAnalysis.suspiciousPatterns.length > 0;

    if (isDangerous) {
      pushThreatToast({
        triggerKey: `protected-visit-${result.id}-${Date.now()}`,
        severity: result.riskLevel === 'Medium' ? 'medium' : 'high',
        title: 'Navigation Blocked: High-Risk URL',
        summary: `ScamShield stopped this link from opening because "${result.urlAnalysis.hostname}" carries active phishing indicators.`,
        matchedPattern: result.urlAnalysis.normalizedUrl,
        recommendations:
          result.safetySteps.length > 0
            ? result.safetySteps.slice(0, 3)
            : [
                'Stay away from this webpage and close the original message.',
                'Navigate to the official website manually instead.',
              ],
      });
    } else {
      pushThreatToast({
        triggerKey: `safe-visit-${result.id}-${Date.now()}`,
        severity: 'safe',
        title: 'Link Passed ScamShield Safety Checks',
        summary: `${result.urlAnalysis.hostname} uses HTTPS and showed no phishing patterns during inspection.`,
        recommendations: [
          'Always double-check the address bar before entering any password.',
        ],
      });
    }
  };

  const toggleStep = (idx: number) => {
    setCheckedSteps((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const riskConfig = {
    High: {
      label: 'High Risk',
      sublabel: 'Likely Scam or Phishing Attempt',
      bannerBg: 'bg-red-50 border-red-200',
      badgeText: 'text-red-800',
      icon: ShieldAlert,
      iconColor: 'text-red-600',
    },
    Medium: {
      label: 'Medium Risk',
      sublabel: 'Suspicious — Verify Before Acting',
      bannerBg: 'bg-amber-50 border-amber-200',
      badgeText: 'text-amber-900',
      icon: AlertTriangle,
      iconColor: 'text-amber-600',
    },
    Low: {
      label: 'Low Risk',
      sublabel: 'No Clear Scam Signs Found',
      bannerBg: 'bg-emerald-50 border-emerald-200',
      badgeText: 'text-emerald-900',
      icon: ShieldCheck,
      iconColor: 'text-emerald-600',
    },
  }[result.riskLevel];

  const RiskIcon = riskConfig.icon;

  const formattedTime = new Date(result.createdAt).toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  const channelLabel =
    result.channel === 'screenshot'
      ? 'Screenshot Analysis'
      : result.channel === 'url'
      ? 'Link Inspection'
      : 'Message Scan';

  const handleDownloadReport = () => {
    const lines = [
      'SCAMSHIELD AI — DIGITAL SAFETY REPORT',
      `Date: ${new Date(result.createdAt).toLocaleString()}`,
      `Scan Type: ${channelLabel}`,
      `Risk Level: ${result.riskLevel} (${result.scamCategory})`,
      '',
      `SUMMARY: ${result.headline}`,
      result.beginnerSummary,
      '',
      'WHY IT LOOKS THIS WAY:',
      result.plainExplanation,
      '',
      'SCANNED CONTENT:',
      result.extractedText,
      '',
      'SUSPICIOUS PHRASES FOUND:',
      ...(result.suspiciousPhrases.length > 0
        ? result.suspiciousPhrases.map((p) => `- "${p.phrase}" (${p.tactic}): ${p.reason}`)
        : ['- None detected']),
      '',
      'RECOMMENDED NEXT STEPS:',
      ...result.safetySteps.map((s, i) => `${i + 1}. ${s}`),
      '',
      'WHAT NOT TO DO:',
      ...result.doNotDo.map((d) => `- ${d}`),
    ];

    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scamshield-report-${result.riskLevel.toLowerCase()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22, ease: 'easeOut' }}
      className="space-y-6"
    >
      {/* Primary Verdict Banner */}
      <section className={`rounded-2xl border p-6 ${riskConfig.bannerBg}`}>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-4">
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ type: 'spring', stiffness: 420, damping: 26 }}
              className="rounded-xl bg-white p-3 border border-slate-200/70 shrink-0"
            >
              <RiskIcon className={`h-7 w-7 ${riskConfig.iconColor}`} />
            </motion.div>
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-600">
                <span className={`font-bold ${riskConfig.badgeText}`}>{riskConfig.label}</span>
                <span className="text-slate-300" aria-hidden="true">/</span>
                <span className="font-medium text-slate-800">{result.scamCategory}</span>
                <span className="text-slate-300" aria-hidden="true">/</span>
                <span>{channelLabel}</span>
                <span className="text-slate-300" aria-hidden="true">/</span>
                <span className="tabular-nums">{formattedTime}</span>
              </div>
              <h2 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight text-balance">
                {result.headline}
              </h2>
              <p className="text-sm sm:text-base text-slate-800 leading-relaxed max-w-3xl">
                {result.beginnerSummary || result.plainExplanation}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <motion.button
              type="button"
              whileTap={{ scale: 0.97 }}
              onClick={() => setChecklistOpen(true)}
              className="inline-flex items-center gap-2 rounded-lg bg-blue-700 px-3.5 py-2 text-xs font-semibold text-white hover:bg-blue-800 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
            >
              <ListChecks className="h-4 w-4" />
              <span>Security Checklist</span>
              <span className="font-mono text-[11px] opacity-90 tabular-nums">
                ({completedTaskCount}/{contextualTasks.length})
              </span>
            </motion.button>
            <motion.button
              type="button"
              whileTap={{ scale: 0.97 }}
              onClick={handleDownloadReport}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="h-4 w-4" />
              Save Report
            </motion.button>
            <motion.button
              type="button"
              whileTap={{ scale: 0.97 }}
              onClick={onScanAnother}
              className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-3.5 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="h-4 w-4" />
              New Scan
            </motion.button>
          </div>
        </div>
      </section>

      {/* Main Split Grid: Highlighted Evidence + Plain Explanation */}
      <div className="grid gap-6 lg:grid-cols-12">
        <div className="lg:col-span-7 space-y-6">
          <div className="rounded-2xl border border-slate-200 bg-white p-6 space-y-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  {result.channel === 'screenshot'
                    ? 'Text Extracted From Your Screenshot'
                    : result.channel === 'url'
                    ? 'Inspected Web Link'
                    : 'Analyzed Message'}
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Suspicious words and links are marked below in plain sight
                </p>
              </div>
            </div>

            {result.imagePreviewDataUrl && (
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 flex items-center gap-4">
                <img
                  src={result.imagePreviewDataUrl}
                  alt="Uploaded suspicious screenshot preview"
                  referrerPolicy="no-referrer"
                  className="h-24 w-20 rounded-lg object-cover border border-slate-200 shrink-0"
                />
                <div className="text-xs text-slate-600 space-y-1">
                  <p className="font-semibold text-slate-900">Screenshot scanned with Gemini Vision</p>
                  <p>We read the text directly from this image so you do not have to retype anything.</p>
                </div>
              </div>
            )}

            <HighlightedText text={result.extractedText} phrases={result.suspiciousPhrases} />
          </div>

          {/* Plain-English Explanation */}
          <div className="rounded-2xl border border-slate-200 bg-white p-6 space-y-3">
            <h3 className="text-base font-bold text-slate-900">Why ScamShield gave this verdict</h3>
            <p className="text-sm sm:text-[15px] text-slate-700 leading-relaxed">
              {result.plainExplanation}
            </p>
          </div>

          {/* Link & Domain Inspection */}
          {result.urlAnalysis && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <Globe className="h-5 w-5 text-blue-600 shrink-0" />
                  <div>
                    <h3 className="text-base font-bold text-slate-900">Link &amp; Domain Inspection</h3>
                    <p className="text-xs text-slate-500 font-mono break-all">
                      {result.urlAnalysis.hostname}
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handleProtectedUrlVisit}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 min-h-[36px] cursor-pointer"
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                    Test Visit (Protected)
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowTechnicalUrl((v) => !v)}
                    className="text-xs font-semibold text-blue-700 hover:underline min-h-[36px] px-2 cursor-pointer"
                  >
                    {showTechnicalUrl ? 'Hide Technical Checks' : 'View Technical Checks'}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                  <span className="text-xs text-slate-500 block">Connection Security</span>
                  <div className="mt-1 flex items-center gap-1.5 text-sm font-semibold text-slate-900">
                    {result.urlAnalysis.isHttps ? (
                      <>
                        <Lock className="h-4 w-4 text-emerald-600" />
                        <span>HTTPS Encrypted</span>
                      </>
                    ) : (
                      <>
                        <LockOpen className="h-4 w-4 text-red-600" />
                        <span>Unencrypted HTTP</span>
                      </>
                    )}
                  </div>
                </div>

                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                  <span className="text-xs text-slate-500 block">Live Domain Status</span>
                  <p className="mt-1 text-sm font-semibold text-slate-900">
                    {result.urlAnalysis.dnsResolved ? 'Active Host' : 'Unverified / Offline'}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 col-span-2 sm:col-span-1">
                  <span className="text-xs text-slate-500 block">Brand Impersonation</span>
                  <p className="mt-1 text-sm font-semibold text-slate-900">
                    {result.urlAnalysis.lookalikeBrand
                      ? `Mimics ${result.urlAnalysis.lookalikeBrand}`
                      : 'None Detected'}
                  </p>
                </div>
              </div>

              {result.urlAnalysis.suspiciousPatterns.length > 0 && (
                <ul className="space-y-2 pt-1">
                  {result.urlAnalysis.suspiciousPatterns.map((pat, i) => (
                    <li key={i} className="flex items-start gap-2.5 text-sm text-slate-700">
                      <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
                      <span>{pat}</span>
                    </li>
                  ))}
                </ul>
              )}

              <AnimatePresence initial={false}>
                {showTechnicalUrl && (
                  <motion.div
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -4 }}
                    transition={{ duration: 0.16 }}
                    className="rounded-xl border border-slate-200 bg-slate-50 p-4 font-mono text-xs text-slate-700 space-y-1.5"
                  >
                    <div>Normalized URL: {result.urlAnalysis.normalizedUrl}</div>
                    <div>Protocol: {result.urlAnalysis.protocol.toUpperCase()}</div>
                    <div>
                      DNS Lookup: {result.urlAnalysis.dnsResolved ? `Resolved (${result.urlAnalysis.resolvedIpsCount} IPs)` : 'No public A/AAAA record'}
                    </div>
                    <div>HTTP Probe Status: {result.urlAnalysis.httpStatus ?? 'No response / Skipped'}</div>
                    <div>
                      Redirects: {result.urlAnalysis.redirected ? `Yes -> ${result.urlAnalysis.finalUrl}` : 'No redirect'}
                    </div>
                    <div>TLD Risk Tier: {result.urlAnalysis.tldRisk}</div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}
        </div>

        {/* Right Column: Beginner-Friendly Action Plan */}
        <div className="lg:col-span-5 space-y-6">
          <div className="rounded-2xl border border-slate-200 bg-white divide-y divide-slate-200 overflow-hidden">
            {/* Interactive Safety Steps */}
            <div className="p-6 space-y-4">
              <div>
                <h3 className="text-base font-bold text-slate-900">What You Should Do Next</h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Follow these simple steps one at a time
                </p>
              </div>

              <div className="space-y-2.5">
                {result.safetySteps.map((step, idx) => {
                  const done = Boolean(checkedSteps[idx]);
                  return (
                    <motion.button
                      key={idx}
                      type="button"
                      whileTap={{ scale: 0.99 }}
                      onClick={() => toggleStep(idx)}
                      className={`w-full flex items-start gap-3 rounded-xl border p-3.5 text-left transition-colors min-h-[44px] cursor-pointer ${
                        done
                          ? 'border-emerald-200 bg-emerald-50/60'
                          : 'border-slate-200 bg-white hover:bg-slate-50'
                      }`}
                    >
                      <span
                        className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md border text-xs font-bold transition-colors ${
                          done
                            ? 'border-emerald-600 bg-emerald-600 text-white'
                            : 'border-slate-300 bg-white text-slate-600'
                        }`}
                      >
                        {done ? <Check className="h-3.5 w-3.5" /> : idx + 1}
                      </span>
                      <span
                        className={`text-sm leading-relaxed ${
                          done ? 'line-through text-slate-500' : 'text-slate-800'
                        }`}
                      >
                        {step}
                      </span>
                    </motion.button>
                  );
                })}
              </div>
            </div>

            {/* What NOT To Do */}
            {result.doNotDo.length > 0 && (
              <div className="p-6 space-y-3 bg-slate-50/40">
                <h3 className="text-base font-bold text-slate-900">What To Avoid</h3>
                <ul className="space-y-2.5">
                  {result.doNotDo.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2.5 text-sm text-slate-700">
                      <XCircle className="h-4 w-4 text-red-600 mt-0.5 shrink-0" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Urgent Help & Assistant CTA */}
          <div className="rounded-2xl border border-blue-200 bg-blue-50/70 p-6 space-y-4">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="h-5 w-5 text-blue-700 mt-0.5 shrink-0" />
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-slate-900">Already clicked or replied?</h3>
                <p className="text-sm text-slate-700 leading-relaxed">
                  {result.urgentHelpNote ||
                    'Do not panic. Ask our Safety Assistant for calm, step-by-step recovery help tailored to this exact message.'}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => onAskAssistant(result)}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-blue-700 px-4 py-3 text-sm font-semibold text-white hover:bg-blue-800 transition-colors min-h-[44px] cursor-pointer"
            >
              <MessageSquare className="h-4 w-4" />
              Ask AI Safety Assistant About This
            </button>
          </div>
        </div>
      </div>

      {/* Context-Aware Security Checklist Slide-Over Drawer */}
      <AnimatePresence>
        {checklistOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="fixed inset-0 z-50 flex justify-end bg-slate-900/40"
            role="dialog"
            aria-modal="true"
            aria-labelledby="security-checklist-title"
            onClick={() => setChecklistOpen(false)}
          >
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', stiffness: 380, damping: 36 }}
              className="w-full max-w-lg bg-white h-full border-l border-slate-200 shadow-2xl flex flex-col justify-between overflow-hidden"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Drawer Header */}
              <div className="border-b border-slate-200 px-6 py-5 flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-xs text-slate-500">
                    <span className="font-semibold text-blue-700">Security Checklist</span>
                    <span className="text-slate-300" aria-hidden="true">/</span>
                    <span>{result.scamCategory}</span>
                  </div>
                  <h2
                    id="security-checklist-title"
                    className="text-lg font-bold text-slate-900 tracking-tight"
                  >
                    Action Plan for {result.riskLevel} Risk Finding
                  </h2>
                  <p className="text-xs text-slate-600">
                    Tailored tasks based on this specific threat. Tap each task to mark it complete.
                  </p>
                </div>
                <button
                  type="button"
                  aria-label="Close Security Checklist"
                  onClick={() => setChecklistOpen(false)}
                  className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-900 min-h-[40px] min-w-[40px] flex items-center justify-center cursor-pointer"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Progress Bar */}
              <div className="border-b border-slate-200 bg-slate-50 px-6 py-3 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-700">Completion Progress</span>
                  <span className="font-mono font-semibold text-slate-900 tabular-nums">
                    {completedTaskCount} of {contextualTasks.length} completed
                  </span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200">
                  <motion.div
                    className="h-full w-full rounded-full bg-blue-700"
                    style={{ transformOrigin: 'left' }}
                    initial={false}
                    animate={{
                      scaleX:
                        contextualTasks.length > 0
                          ? completedTaskCount / contextualTasks.length
                          : 0,
                    }}
                    transition={{ type: 'spring', stiffness: 320, damping: 30 }}
                  />
                </div>
              </div>

              {/* Scrollable Interactive Tasks */}
              <div className="flex-1 overflow-y-auto p-6 space-y-3">
                {contextualTasks.map((task) => {
                  const isDone = Boolean(completedTasks[task.id]);
                  return (
                    <motion.button
                      key={task.id}
                      type="button"
                      whileTap={{ scale: 0.99 }}
                      onClick={() => toggleChecklistTask(task.id)}
                      className={`w-full flex items-start gap-3.5 rounded-xl border p-4 text-left transition-colors min-h-[56px] cursor-pointer ${
                        isDone
                          ? 'border-emerald-200 bg-emerald-50/60'
                          : 'border-slate-200 bg-white hover:bg-slate-50'
                      }`}
                    >
                      <motion.span
                        animate={{ scale: isDone ? [1, 1.15, 1] : 1 }}
                        transition={{ duration: 0.2 }}
                        className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md border transition-colors ${
                          isDone
                            ? 'border-emerald-600 bg-emerald-600 text-white'
                            : 'border-slate-300 bg-white text-transparent'
                        }`}
                      >
                        <Check className="h-3.5 w-3.5" />
                      </motion.span>

                      <div className="flex-1 space-y-1 min-w-0">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span
                            className={`text-sm font-bold ${
                              isDone ? 'line-through text-slate-500' : 'text-slate-900'
                            }`}
                          >
                            {task.title}
                          </span>
                          <span
                            className={`text-[11px] font-semibold ${
                              task.priority === 'Immediate' ? 'text-red-700' : 'text-slate-500'
                            }`}
                          >
                            {task.priority}
                          </span>
                        </div>
                        <p
                          className={`text-xs leading-relaxed ${
                            isDone ? 'text-slate-400' : 'text-slate-600'
                          }`}
                        >
                          {task.detail}
                        </p>
                      </div>
                    </motion.button>
                  );
                })}
              </div>

              {/* Drawer Footer */}
              <div className="border-t border-slate-200 bg-slate-50 px-6 py-4 flex flex-wrap items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={() => setCompletedTasks({})}
                  className="text-xs font-semibold text-slate-600 hover:text-slate-900 px-2 py-1.5 cursor-pointer"
                >
                  Reset Tasks
                </button>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setChecklistOpen(false);
                      onAskAssistant(result);
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 min-h-[40px] cursor-pointer"
                  >
                    <MessageSquare className="h-3.5 w-3.5" />
                    Ask Assistant
                  </button>
                  <button
                    type="button"
                    onClick={() => setChecklistOpen(false)}
                    className="rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 min-h-[40px] cursor-pointer"
                  >
                    Done
                  </button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
