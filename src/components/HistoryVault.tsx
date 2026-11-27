import { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle,
  Fingerprint,
  KeyRound,
  Lock,
  LockOpen,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import type { ScanResult } from '../types/scam';
import {
  clearVaultConfig,
  enrollBiometricPasskey,
  enrollVaultPin,
  isPlatformBiometricAvailable,
  verifyBiometricPasskey,
  verifyVaultPin,
  type VaultConfig,
} from '../utils/biometric';

interface HistoryVaultProps {
  history: ScanResult[];
  vaultConfig: VaultConfig | null;
  isVaultUnlocked: boolean;
  onVaultConfigChange: (config: VaultConfig | null) => void;
  onSetVaultUnlocked: (unlocked: boolean) => void;
  onSelectScan: (scan: ScanResult) => void;
  onDeleteScan: (id: string) => void;
  onClearAll: () => void;
}

export function HistoryVault({
  history,
  vaultConfig,
  isVaultUnlocked,
  onVaultConfigChange,
  onSetVaultUnlocked,
  onSelectScan,
  onDeleteScan,
  onClearAll,
}: HistoryVaultProps) {
  const [biometricSupported, setBiometricSupported] = useState<boolean>(false);
  const [pinInput, setPinInput] = useState('');
  const [setupPinInput, setSetupPinInput] = useState('');
  const [showPinSetup, setShowPinSetup] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    isPlatformBiometricAvailable().then(setBiometricSupported);
  }, []);

  const isLocked = Boolean(vaultConfig?.enabled) && !isVaultUnlocked;

  const handleEnableBiometrics = async () => {
    setErrorMsg(null);
    setStatusMessage(null);
    setBusy(true);
    const res = await enrollBiometricPasskey();
    setBusy(false);
    if (res.ok) {
      onVaultConfigChange(res.config);
      onSetVaultUnlocked(true);
      setStatusMessage('Biometric Privacy Vault enabled using your device Passkey (Face ID / Touch ID / Windows Hello).');
    } else {
      setErrorMsg(res.error);
      setShowPinSetup(true);
    }
  };

  const handleEnablePin = async () => {
    if (!/^\d{4,6}$/.test(setupPinInput.trim())) {
      setErrorMsg('Please enter a 4 to 6 digit numeric PIN.');
      return;
    }
    setErrorMsg(null);
    setBusy(true);
    const cfg = await enrollVaultPin(setupPinInput.trim());
    setBusy(false);
    onVaultConfigChange(cfg);
    onSetVaultUnlocked(true);
    setSetupPinInput('');
    setShowPinSetup(false);
    setStatusMessage('4-digit Vault PIN protection enabled for your scan history.');
  };

  const handleUnlock = async () => {
    if (!vaultConfig) return;
    setErrorMsg(null);
    setBusy(true);

    if (vaultConfig.mode === 'webauthn') {
      const res = await verifyBiometricPasskey(vaultConfig);
      setBusy(false);
      if (res.ok) {
        onSetVaultUnlocked(true);
      } else {
        setErrorMsg(res.error || 'Biometric unlock failed.');
      }
      return;
    }

    const ok = await verifyVaultPin(pinInput.trim(), vaultConfig);
    setBusy(false);
    if (ok) {
      setPinInput('');
      onSetVaultUnlocked(true);
    } else {
      setErrorMsg('Incorrect Vault PIN. Please try again.');
    }
  };

  const handleDisableVault = () => {
    clearVaultConfig();
    onVaultConfigChange(null);
    onSetVaultUnlocked(true);
    setStatusMessage('Privacy Vault lock removed.');
    setErrorMsg(null);
  };

  return (
    <div className="space-y-6">
      {/* Header & Biometric Vault Control Bar */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Scan History &amp; Biometric Privacy Vault
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Revisit past scan reports safely. Lock sensitive screenshots and bank alerts with device biometrics or a Vault PIN.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {!vaultConfig?.enabled ? (
            <>
              <button
                type="button"
                disabled={busy}
                onClick={handleEnableBiometrics}
                className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-xs font-semibold text-white hover:bg-slate-800 transition-colors min-h-[42px] whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Fingerprint className="h-4 w-4" />
                {biometricSupported ? 'Enable Biometric Lock' : 'Enable Passkey / Biometric'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowPinSetup((v) => !v);
                  setErrorMsg(null);
                }}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors min-h-[42px] whitespace-nowrap shrink-0 cursor-pointer"
              >
                <KeyRound className="h-4 w-4" />
                Set Vault PIN
              </button>
            </>
          ) : (
            <>
              {isVaultUnlocked ? (
                <button
                  type="button"
                  onClick={() => onSetVaultUnlocked(false)}
                  className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-xs font-semibold text-white hover:bg-slate-800 transition-colors min-h-[42px] whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Lock className="h-4 w-4" />
                  Lock Vault Now
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handleUnlock}
                  className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 transition-colors min-h-[42px] whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <LockOpen className="h-4 w-4" />
                  Unlock Vault
                </button>
              )}
              <button
                type="button"
                onClick={handleDisableVault}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors min-h-[42px] whitespace-nowrap shrink-0 cursor-pointer"
              >
                Disable Lock
              </button>
            </>
          )}
        </div>
      </div>

      {/* Vault Status / PIN Setup */}
      <AnimatePresence>
        {showPinSetup && !vaultConfig?.enabled && (
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.18 }}
            className="rounded-2xl border border-slate-200 bg-white p-6 space-y-4"
          >
            <div className="flex items-start gap-3">
              <KeyRound className="h-5 w-5 text-blue-700 mt-0.5 shrink-0" />
              <div>
                <h2 className="text-base font-bold text-slate-900">Create a Privacy Vault PIN</h2>
                <p className="text-xs text-slate-600 mt-0.5">
                  Protects your saved screenshots and scan history on this device with a 4–6 digit PIN.
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <input
                type="password"
                inputMode="numeric"
                maxLength={6}
                value={setupPinInput}
                onChange={(e) => setSetupPinInput(e.target.value.replace(/\D/g, ''))}
                placeholder="Enter 4-6 digit PIN"
                className="rounded-xl border border-slate-300 bg-slate-50 px-4 py-2.5 font-mono text-sm text-slate-900 focus:border-blue-600 focus:bg-white focus:outline-none min-h-[44px]"
              />
              <button
                type="button"
                disabled={busy}
                onClick={handleEnablePin}
                className="rounded-xl bg-blue-700 px-5 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 min-h-[44px] cursor-pointer"
              >
                Save Vault PIN
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {statusMessage && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900"
          >
            {statusMessage}
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {errorMsg && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
          >
            {errorMsg}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Locked State Overlay */}
      <AnimatePresence mode="wait">
        {isLocked ? (
          <motion.div
            key="vault-locked"
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.18 }}
            className="rounded-2xl border border-slate-200 bg-white p-10 text-center space-y-5"
          >
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-slate-800">
            {vaultConfig?.mode === 'webauthn' ? (
              <Fingerprint className="h-7 w-7" />
            ) : (
              <Lock className="h-7 w-7" />
            )}
          </div>
          <div className="space-y-1.5 max-w-md mx-auto">
            <h2 className="text-lg font-bold text-slate-900">Scan History Protected</h2>
            <p className="text-sm text-slate-600">
              {vaultConfig?.mode === 'webauthn'
                ? 'Verify with Touch ID, Face ID, or your device passkey to view your saved scam evidence.'
                : 'Enter your Privacy Vault PIN to view your saved scam evidence and screenshots.'}
            </p>
          </div>

          {vaultConfig?.mode === 'pin' ? (
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <input
                type="password"
                inputMode="numeric"
                maxLength={6}
                value={pinInput}
                onChange={(e) => setPinInput(e.target.value.replace(/\D/g, ''))}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleUnlock();
                }}
                placeholder="Enter Vault PIN"
                className="rounded-xl border border-slate-300 bg-slate-50 px-4 py-2.5 font-mono text-sm text-center text-slate-900 focus:border-blue-600 focus:bg-white focus:outline-none min-h-[44px] w-48"
              />
              <button
                type="button"
                disabled={busy}
                onClick={handleUnlock}
                className="rounded-xl bg-blue-700 px-6 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 min-h-[44px] cursor-pointer"
              >
                Unlock History
              </button>
            </div>
          ) : (
            <button
              type="button"
              disabled={busy}
              onClick={handleUnlock}
              className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-6 py-3 text-sm font-semibold text-white hover:bg-blue-800 min-h-[44px] cursor-pointer"
            >
              <Fingerprint className="h-4 w-4" />
              Verify with Biometrics
            </button>
          )}
          </motion.div>
        ) : (
          <motion.div
            key="vault-unlocked"
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.18 }}
            className="space-y-4"
          >
            {history.length > 0 && (
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500 tabular-nums">
                  {history.length} saved scan{history.length === 1 ? '' : 's'}
                </span>
                <button
                  type="button"
                  onClick={onClearAll}
                  className="text-xs font-semibold text-red-600 hover:underline cursor-pointer"
                >
                  Clear All History
                </button>
              </div>
            )}

            {history.length === 0 ? (
              <div className="rounded-2xl border border-slate-200 bg-white p-10 text-center space-y-2">
                <p className="text-base font-semibold text-slate-900">Your scan history is empty</p>
                <p className="text-sm text-slate-500">
                  Any message, screenshot, or URL you scan will automatically appear here for easy reference.
                </p>
              </div>
            ) : (
              <div className="rounded-2xl border border-slate-200 bg-white divide-y divide-slate-200 overflow-hidden">
                {history.map((scan) => {
                  const RiskIcon =
                    scan.riskLevel === 'High'
                      ? ShieldAlert
                      : scan.riskLevel === 'Medium'
                      ? AlertTriangle
                      : ShieldCheck;
                  const riskColor =
                    scan.riskLevel === 'High'
                      ? 'text-red-700'
                      : scan.riskLevel === 'Medium'
                      ? 'text-amber-700'
                      : 'text-emerald-700';

                  return (
                    <div
                      key={scan.id}
                      className="p-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between hover:bg-slate-50/70 transition-colors"
                    >
                      <button
                        type="button"
                        onClick={() => onSelectScan(scan)}
                        className="flex-1 text-left space-y-1.5 cursor-pointer"
                      >
                        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-500">
                          <span className={`inline-flex items-center gap-1 font-bold ${riskColor}`}>
                            <RiskIcon className="h-3.5 w-3.5" />
                            {scan.riskLevel} Risk
                          </span>
                          <span className="text-slate-300" aria-hidden="true">/</span>
                          <span className="font-medium text-slate-700">{scan.scamCategory}</span>
                          <span className="text-slate-300" aria-hidden="true">/</span>
                          <span className="capitalize">{scan.channel}</span>
                          <span className="text-slate-300" aria-hidden="true">/</span>
                          <span className="tabular-nums">
                            {new Date(scan.createdAt).toLocaleString([], {
                              month: 'short',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </span>
                        </div>
                        <h3 className="text-base font-bold text-slate-900">{scan.headline}</h3>
                        <p className="text-sm text-slate-600 line-clamp-2">{scan.inputSummary}</p>
                      </button>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() => onSelectScan(scan)}
                          className="rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 min-h-[40px] cursor-pointer"
                        >
                          Open Report
                        </button>
                        <button
                          type="button"
                          aria-label="Delete scan from history"
                          onClick={() => onDeleteScan(scan.id)}
                          className="rounded-lg border border-slate-200 p-2.5 text-slate-500 hover:bg-red-50 hover:text-red-600 min-h-[40px] min-w-[40px] flex items-center justify-center cursor-pointer"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
