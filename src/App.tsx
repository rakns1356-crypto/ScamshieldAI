/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from 'react';
import { AnimatePresence, MotionConfig, motion } from 'motion/react';
import {
  BarChart3,
  BookOpen,
  Fingerprint,
  History,
  Lock,
  Menu,
  MessageSquare,
  Plus,
  ShieldCheck,
  X,
} from 'lucide-react';
import { HistoryVault } from './components/HistoryVault';
import { PhishingDashboard } from './components/PhishingDashboard';
import { SafetyChatbot } from './components/SafetyChatbot';
import { SafetyGuide } from './components/SafetyGuide';
import { ScannerWorkspace } from './components/ScannerWorkspace';
import { ToastProvider, useThreatToast } from './components/ToastProvider';
import type { ScanChannel, ScanResult } from './types/scam';
import { loadVaultConfig, type VaultConfig } from './utils/biometric';
import { INITIAL_SAMPLE_HISTORY } from './utils/sampleGenerator';

type NavView = 'scanner' | 'dashboard' | 'history' | 'chat' | 'guide';

const HISTORY_STORAGE_KEY = 'scamshield_scan_history_v1';

function loadInitialHistory(): ScanResult[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return INITIAL_SAMPLE_HISTORY;
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ScanResult[]) : INITIAL_SAMPLE_HISTORY;
  } catch {
    return INITIAL_SAMPLE_HISTORY;
  }
}

function ScamShieldWorkspace({
  activeView,
  setActiveView,
  chatScanContext,
  setChatScanContext,
}: {
  activeView: NavView;
  setActiveView: (v: NavView) => void;
  chatScanContext: ScanResult | null;
  setChatScanContext: (s: ScanResult | null) => void;
}) {
  const { pushThreatToast } = useThreatToast();
  const [scannerTab, setScannerTab] = useState<ScanChannel>('message');
  const [activeResult, setActiveResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>(loadInitialHistory);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [vaultConfig, setVaultConfig] = useState<VaultConfig | null>(() => loadVaultConfig());
  const [isVaultUnlocked, setIsVaultUnlocked] = useState<boolean>(() => !loadVaultConfig()?.enabled);

  useEffect(() => {
    try {
      // Avoid exceeding localStorage quota with very large inline base64 previews
      const compactHistory = history.slice(0, 30).map((item) => ({
        ...item,
        imagePreviewDataUrl:
          item.imagePreviewDataUrl && item.imagePreviewDataUrl.length < 300_000
            ? item.imagePreviewDataUrl
            : undefined,
      }));
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(compactHistory));
    } catch {
      // Ignore storage quota warnings
    }
  }, [history]);

  const handleScanComplete = (result: ScanResult) => {
    setActiveResult(result);
    setHistory((prev) => [result, ...prev]);
    setChatScanContext(result);

    if (
      result.riskLevel === 'High' ||
      (result.riskLevel === 'Medium' && (result.urlAnalysis?.suspiciousPatterns.length || 0) > 0)
    ) {
      pushThreatToast({
        triggerKey: `scan-${result.id}`,
        severity: result.riskLevel === 'High' ? 'high' : 'medium',
        title:
          result.riskLevel === 'High'
            ? `High-Risk Threat Detected: ${result.scamCategory}`
            : `Suspicious Pattern Flagged: ${result.scamCategory}`,
        summary: result.beginnerSummary || result.headline,
        matchedPattern:
          result.suspiciousPhrases[0]?.phrase || result.urlAnalysis?.hostname,
        recommendations:
          result.safetySteps.length > 0
            ? result.safetySteps.slice(0, 3)
            : [
                'Do not click links, reply, or share personal details.',
                'Verify directly through an official app or phone number.',
              ],
      });
    }
  };

  const handleSelectScanFromList = (scan: ScanResult) => {
    setActiveResult(scan);
    setScannerTab(scan.channel);
    setActiveView('scanner');
    setMobileMenuOpen(false);
  };

  const handleAskAssistant = (scan: ScanResult) => {
    setChatScanContext(scan);
    setActiveView('chat');
    setMobileMenuOpen(false);
  };

  const handleStartNewScan = (channel: ScanChannel = 'message') => {
    setActiveResult(null);
    setScannerTab(channel);
    setActiveView('scanner');
    setMobileMenuOpen(false);
  };

  const handleDeleteScan = (id: string) => {
    setHistory((prev) => prev.filter((item) => item.id !== id));
    if (activeResult?.id === id) {
      setActiveResult(null);
    }
  };

  const handleClearAll = () => {
    setHistory([]);
    setActiveResult(null);
  };

  const navItems: Array<{ id: NavView; label: string; icon: typeof ShieldCheck }> = [
    { id: 'scanner', label: 'Scam Scanner', icon: ShieldCheck },
    { id: 'dashboard', label: 'Phishing Dashboard', icon: BarChart3 },
    { id: 'history', label: 'History & Vault', icon: History },
    { id: 'chat', label: 'Safety Assistant', icon: MessageSquare },
    { id: 'guide', label: 'Beginner Guide', icon: BookOpen },
  ];

  const currentBreadcrumb =
    activeView === 'scanner'
      ? activeResult
        ? 'Scan Report'
        : scannerTab === 'screenshot'
        ? 'Screenshot Analyzer'
        : scannerTab === 'url'
        ? 'Link Inspector'
        : 'Message Scanner'
      : navItems.find((n) => n.id === activeView)?.label || 'Workspace';

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col lg:flex-row">
      {/* Mobile Sidebar Backdrop */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.16 }}
            className="fixed inset-0 z-40 bg-slate-900/40 lg:hidden"
            onClick={() => setMobileMenuOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Left Sidebar Navigation */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 border-r border-slate-200 bg-white flex flex-col justify-between transition-transform duration-200 lg:static lg:translate-x-0 ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div>
          <div className="h-16 px-5 border-b border-slate-200 flex items-center justify-between">
            <button
              type="button"
              onClick={() => handleStartNewScan('message')}
              className="flex items-center gap-2.5 text-left whitespace-nowrap shrink-0 cursor-pointer"
            >
              <ShieldCheck className="h-6 w-6 text-blue-700 shrink-0" />
              <span className="font-display text-lg font-bold tracking-tight text-slate-900">
                ScamShield AI
              </span>
            </button>
            <button
              type="button"
              aria-label="Close menu"
              onClick={() => setMobileMenuOpen(false)}
              className="lg:hidden rounded-lg p-1.5 text-slate-500 hover:bg-slate-100"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          <nav aria-label="Primary Navigation" className="p-3 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setActiveView(item.id);
                    setMobileMenuOpen(false);
                  }}
                  className={`relative w-full flex items-center gap-3 rounded-xl px-3.5 py-2.5 text-sm font-medium transition-colors min-h-[42px] whitespace-nowrap cursor-pointer ${
                    isActive
                      ? 'text-blue-800 font-semibold'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                  }`}
                >
                  {isActive && (
                    <motion.span
                      layoutId="sidebar-nav-active"
                      transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                      className="absolute inset-0 rounded-xl bg-blue-50"
                    />
                  )}
                  <Icon
                    className={`relative z-10 h-4 w-4 shrink-0 ${
                      isActive ? 'text-blue-700' : 'text-slate-400'
                    }`}
                  />
                  <span className="relative z-10">{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Bottom Privacy Vault Card */}
        <div className="p-4 border-t border-slate-200 space-y-3">
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-3.5 space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
              {vaultConfig?.enabled ? (
                <Lock className="h-4 w-4 text-blue-700 shrink-0" />
              ) : (
                <Fingerprint className="h-4 w-4 text-slate-500 shrink-0" />
              )}
              <span>Biometric Privacy Vault</span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              {vaultConfig?.enabled
                ? isVaultUnlocked
                  ? 'Vault unlocked for this session.'
                  : 'History is locked with your biometric key or PIN.'
                : 'Protect saved screenshots with Touch ID, Face ID, or PIN.'}
            </p>
            <button
              type="button"
              onClick={() => {
                setActiveView('history');
                setMobileMenuOpen(false);
              }}
              className="text-xs font-semibold text-blue-700 hover:underline cursor-pointer"
            >
              {vaultConfig?.enabled ? 'Manage Vault' : 'Enable Protection'}
            </button>
          </div>
          <p className="text-[11px] text-slate-400 px-1">
            Think Before You Click.
          </p>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Compact Top Header Bar */}
        <header className="sticky top-0 z-30 h-16 border-b border-slate-200 bg-white/95 backdrop-blur-xs px-4 sm:px-8 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label="Open navigation menu"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden rounded-lg border border-slate-200 p-2 text-slate-700 hover:bg-slate-100 min-h-[40px] min-w-[40px] flex items-center justify-center cursor-pointer"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex items-center gap-2 text-xs sm:text-sm text-slate-500 truncate">
              <span className="font-semibold text-slate-900 hidden sm:inline">ScamShield AI</span>
              <span className="hidden sm:inline text-slate-300" aria-hidden="true">
                /
              </span>
              <span className="font-medium text-slate-700 truncate">{currentBreadcrumb}</span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            {vaultConfig?.enabled && isVaultUnlocked && (
              <button
                type="button"
                onClick={() => {
                  setIsVaultUnlocked(false);
                  setActiveView('history');
                }}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Lock className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Lock Vault</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => handleStartNewScan('message')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="h-4 w-4" />
              New Scan
            </button>
          </div>
        </header>

        {/* Main Viewport */}
        <main className="flex-1 px-4 sm:px-8 py-6 sm:py-8">
          <div className="mx-auto max-w-[1160px]">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeView}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.16, ease: 'easeOut' }}
              >
                {activeView === 'scanner' && (
                  <ScannerWorkspace
                    activeTab={scannerTab}
                    onTabChange={setScannerTab}
                    activeResult={activeResult}
                    onScanComplete={handleScanComplete}
                    onClearResult={() => setActiveResult(null)}
                    onAskAssistant={handleAskAssistant}
                  />
                )}

                {activeView === 'dashboard' && (
                  <PhishingDashboard
                    history={history}
                    onSelectScan={handleSelectScanFromList}
                    onStartNewScan={handleStartNewScan}
                  />
                )}

                {activeView === 'history' && (
                  <HistoryVault
                    history={history}
                    vaultConfig={vaultConfig}
                    isVaultUnlocked={isVaultUnlocked}
                    onVaultConfigChange={setVaultConfig}
                    onSetVaultUnlocked={setIsVaultUnlocked}
                    onSelectScan={handleSelectScanFromList}
                    onDeleteScan={handleDeleteScan}
                    onClearAll={handleClearAll}
                  />
                )}

                {activeView === 'chat' && (
                  <SafetyChatbot
                    activeScanContext={chatScanContext}
                    onClearContext={() => setChatScanContext(null)}
                  />
                )}

                {activeView === 'guide' && (
                  <SafetyGuide
                    onOpenScanner={() => handleStartNewScan('message')}
                    onOpenChat={() => setActiveView('chat')}
                  />
                )}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  const [activeView, setActiveView] = useState<NavView>('scanner');
  const [chatScanContext, setChatScanContext] = useState<ScanResult | null>(null);

  return (
    <MotionConfig reducedMotion="user">
      <ToastProvider onOpenSafetyAssistant={() => setActiveView('chat')}>
        <ScamShieldWorkspace
          activeView={activeView}
          setActiveView={setActiveView}
          chatScanContext={chatScanContext}
          setChatScanContext={setChatScanContext}
        />
      </ToastProvider>
    </MotionConfig>
  );
}
