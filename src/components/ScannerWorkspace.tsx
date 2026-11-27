import { useEffect, useRef, useState } from 'react';
import {
  ExternalLink,
  FileText,
  Globe,
  ImagePlus,
  Loader2,
  Search,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import type { ScanChannel, ScanResult } from '../types/scam';
import {
  SAMPLE_JOB_CHAT_IMAGE,
  SAMPLE_MESSAGES,
  SAMPLE_URLS,
  generateSampleBankSmsScreenshot,
} from '../utils/sampleGenerator';
import {
  detectHighRiskUrl,
  detectMaliciousMessagePattern,
} from '../utils/threatPatternDetector';
import { ScanResultView } from './ScanResultView';
import { useThreatToast } from './ToastProvider';

interface ScannerWorkspaceProps {
  activeTab: ScanChannel;
  onTabChange: (tab: ScanChannel) => void;
  activeResult: ScanResult | null;
  onScanComplete: (result: ScanResult) => void;
  onClearResult: () => void;
  onAskAssistant: (scan: ScanResult) => void;
}

export function ScannerWorkspace({
  activeTab,
  onTabChange,
  activeResult,
  onScanComplete,
  onClearResult,
  onAskAssistant,
}: ScannerWorkspaceProps) {
  const [messageText, setMessageText] = useState('');
  const [sourceType, setSourceType] = useState<'SMS' | 'WhatsApp' | 'Email'>('SMS');
  const [urlInput, setUrlInput] = useState('');
  const [screenshotDataUrl, setScreenshotDataUrl] = useState<string>('');
  const [screenshotMime, setScreenshotMime] = useState<string>('image/png');
  const [screenshotNote, setScreenshotNote] = useState<string>('');
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { pushThreatToast } = useThreatToast();

  // Real-time live pattern alert as user types or pastes suspicious messages/URLs
  useEffect(() => {
    if (activeResult) return;
    const timer = window.setTimeout(() => {
      if (activeTab === 'url' && urlInput.trim().length >= 6) {
        const match = detectHighRiskUrl(urlInput);
        if (match) {
          pushThreatToast({
            ...match,
            actionLabel: 'Inspect Full URL',
            onAction: () => handleScanUrl(urlInput),
          });
        }
      } else if (activeTab === 'message' && messageText.trim().length >= 16) {
        const match = detectMaliciousMessagePattern(messageText);
        if (match) {
          pushThreatToast({
            ...match,
            actionLabel: 'Run Full AI Scan',
            onAction: () => handleScanMessage(messageText, sourceType),
          });
        }
      }
    }, 350);

    return () => window.clearTimeout(timer);
  }, [activeTab, urlInput, messageText, activeResult]);

  const handleTestVisitUrl = () => {
    const raw = urlInput.trim();
    if (!raw) {
      setErrorMsg('Enter a link above to test Safe Visit Guard.');
      return;
    }
    const match = detectHighRiskUrl(raw);
    if (match) {
      pushThreatToast({
        ...match,
        triggerKey: `visit-block-${raw}-${Date.now()}`,
        title: `Blocked Visit to High-Risk URL`,
        summary: `ScamShield prevented opening "${raw}" because it shows clear phishing signals.`,
        actionLabel: 'Run Deep DNS Check',
        onAction: () => handleScanUrl(raw),
      });
      return;
    }

    pushThreatToast({
      triggerKey: `visit-check-${raw}-${Date.now()}`,
      severity: 'medium',
      title: 'Verify Before Opening External Link',
      summary: 'Run Check Link Safety first so ScamShield can verify DNS status and redirects before you visit.',
      matchedPattern: raw,
      recommendations: [
        'Click Check Link Safety to run a live server-side inspection.',
        'Only open links from senders and companies you know.',
      ],
      actionLabel: 'Check Link Safety',
      onAction: () => handleScanUrl(raw),
    });
  };

  const handleScanMessage = async (textOverride?: string, sourceOverride?: 'SMS' | 'WhatsApp' | 'Email') => {
    const content = (textOverride ?? messageText).trim();
    if (content.length < 5) {
      setErrorMsg('Please paste a message or choose one of the sample messages below.');
      return;
    }
    setErrorMsg(null);
    setIsLoading(true);
    try {
      const res = await fetch('/api/scan/message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: content,
          sourceType: sourceOverride ?? sourceType,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Could not analyze the message.');
      }
      onScanComplete(data as ScanResult);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Something went wrong while scanning.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleScanUrl = async (urlOverride?: string) => {
    const targetUrl = (urlOverride ?? urlInput).trim();
    if (!targetUrl) {
      setErrorMsg('Please enter a website link (for example, https://example.com).');
      return;
    }
    setErrorMsg(null);
    setIsLoading(true);
    try {
      const res = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Could not inspect the URL.');
      }
      onScanComplete(data as ScanResult);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Unable to check this link right now.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileSelected = (file: File) => {
    if (!file.type.startsWith('image/')) {
      setErrorMsg('Please choose an image file (PNG, JPG, or WebP screenshot).');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setErrorMsg('Screenshot must be smaller than 10 MB.');
      return;
    }
    setErrorMsg(null);
    setScreenshotMime(file.type || 'image/png');
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        setScreenshotDataUrl(reader.result);
      }
    };
    reader.readAsDataURL(file);
  };

  const handleLoadSampleBankScreenshot = () => {
    setErrorMsg(null);
    const dataUrl = generateSampleBankSmsScreenshot();
    if (dataUrl) {
      setScreenshotDataUrl(dataUrl);
      setScreenshotMime('image/png');
      setScreenshotNote('Received this text claiming to be my bank');
    }
  };

  const handleLoadSampleJobScreenshot = async () => {
    setErrorMsg(null);
    try {
      const response = await fetch(SAMPLE_JOB_CHAT_IMAGE);
      const blob = await response.blob();
      const reader = new FileReader();
      reader.onload = () => {
        if (typeof reader.result === 'string') {
          setScreenshotDataUrl(reader.result);
          setScreenshotMime('image/jpeg');
          setScreenshotNote('Someone messaged me offering a remote job');
        }
      };
      reader.readAsDataURL(blob);
    } catch {
      setErrorMsg('Could not load the sample job screenshot. Please upload any image from your device.');
    }
  };

  const handleScanScreenshot = async () => {
    if (!screenshotDataUrl) {
      setErrorMsg('Please upload a screenshot or load one of the sample screenshots first.');
      return;
    }
    setErrorMsg(null);
    setIsLoading(true);
    try {
      const res = await fetch('/api/scan/screenshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          imageBase64: screenshotDataUrl,
          mimeType: screenshotMime,
          contextNote: screenshotNote,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Could not analyze the screenshot.');
      }
      const scanResult: ScanResult = {
        ...(data as ScanResult),
        imagePreviewDataUrl: screenshotDataUrl,
      };
      onScanComplete(scanResult);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Unable to analyze screenshot right now.');
    } finally {
      setIsLoading(false);
    }
  };

  if (activeResult) {
    return (
      <ScanResultView
        result={activeResult}
        onAskAssistant={onAskAssistant}
        onScanAnother={() => {
          onClearResult();
          setErrorMsg(null);
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Intro Hero Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="space-y-2 max-w-2xl">
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight text-balance">
            Think Before You Click. Check Any Message, Screenshot, or Link.
          </h1>
          <p className="text-sm sm:text-base text-slate-600 leading-relaxed">
            Paste a suspicious text, upload a screenshot of a conversation, or inspect a web address. ScamShield AI highlights hidden red flags and explains what to do in plain language.
          </p>
        </div>

        {/* Segmented Scanner Mode Selector */}
        <div
          role="tablist"
          aria-label="Scanner Mode"
          className="inline-flex items-center gap-1 rounded-xl border border-slate-200 bg-slate-100 p-1 self-start lg:self-auto"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'message'}
            onClick={() => {
              onTabChange('message');
              setErrorMsg(null);
            }}
            className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'message'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <FileText className="h-4 w-4" />
            Message
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'screenshot'}
            onClick={() => {
              onTabChange('screenshot');
              setErrorMsg(null);
            }}
            className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'screenshot'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <ImagePlus className="h-4 w-4" />
            Screenshot
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'url'}
            onClick={() => {
              onTabChange('url');
              setErrorMsg(null);
            }}
            className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'url'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Globe className="h-4 w-4" />
            URL Check
          </button>
        </div>
      </div>

      {/* Main Scanner Card */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 space-y-6">
        {activeTab === 'message' && (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-bold text-slate-900">Smart Message Scanner</h2>
                <p className="text-sm text-slate-500">
                  Copy and paste an SMS, WhatsApp message, or email you feel unsure about.
                </p>
              </div>
              <div className="flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 p-1">
                {(['SMS', 'WhatsApp', 'Email'] as const).map((type) => (
                  <button
                    key={type}
                    type="button"
                    onClick={() => setSourceType(type)}
                    className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      sourceType === type
                        ? 'bg-white text-slate-900 shadow-xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>

            <textarea
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              rows={6}
              placeholder="Example: URGENT! Your bank card has been locked. Verify at http://..."
              className="w-full rounded-xl border border-slate-300 bg-slate-50/50 p-4 text-[15px] text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-600/20"
            />

            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-medium text-slate-500 mr-1">Try an example:</span>
                {SAMPLE_MESSAGES.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => {
                      setMessageText(preset.text);
                      setSourceType(preset.sourceType);
                      setErrorMsg(null);
                    }}
                    className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100 transition-colors min-h-[36px] cursor-pointer"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>

              <button
                type="button"
                disabled={isLoading}
                onClick={() => handleScanMessage()}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-700 px-6 py-3 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors min-h-[44px] whitespace-nowrap shrink-0 cursor-pointer"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Scanning Message...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-4 w-4" />
                    Scan Message
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {activeTab === 'screenshot' && (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-bold text-slate-900">Screenshot Scam Analyzer</h2>
                <p className="text-sm text-slate-500">
                  Upload a screenshot of any suspicious text, bank alert, or chat. We read it automatically.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={handleLoadSampleBankScreenshot}
                  className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 transition-colors min-h-[40px] cursor-pointer"
                >
                  Load Sample Bank SMS
                </button>
                <button
                  type="button"
                  onClick={handleLoadSampleJobScreenshot}
                  className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 transition-colors min-h-[40px] cursor-pointer"
                >
                  Load Sample Job Chat
                </button>
              </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-12 items-stretch">
              <div className="lg:col-span-7">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/webp,image/gif"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleFileSelected(f);
                  }}
                />
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setIsDragging(true);
                  }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setIsDragging(false);
                    const f = e.dataTransfer.files?.[0];
                    if (f) handleFileSelected(f);
                  }}
                  onClick={() => fileInputRef.current?.click()}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
                  }}
                  className={`flex h-full min-h-[260px] flex-col items-center justify-center rounded-xl border-2 border-dashed p-6 text-center transition-colors cursor-pointer ${
                    isDragging
                      ? 'border-blue-600 bg-blue-50'
                      : 'border-slate-300 bg-slate-50/60 hover:border-slate-400 hover:bg-slate-50'
                  }`}
                >
                  <Upload className="h-9 w-9 text-slate-400 mb-3" />
                  <p className="text-sm font-semibold text-slate-900">
                    Click to choose a screenshot, or drag and drop it here
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Supports PNG, JPG, or WebP images up to 10 MB
                  </p>
                </div>
              </div>

              <div className="lg:col-span-5 flex flex-col justify-between gap-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
                {screenshotDataUrl ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-700">Selected Screenshot</span>
                      <button
                        type="button"
                        onClick={() => setScreenshotDataUrl('')}
                        className="text-xs font-medium text-red-600 hover:underline cursor-pointer"
                      >
                        Remove
                      </button>
                    </div>
                    <img
                      src={screenshotDataUrl}
                      alt="Screenshot ready for AI analysis"
                      referrerPolicy="no-referrer"
                      className="mx-auto max-h-56 rounded-lg border border-slate-200 object-contain bg-white"
                    />
                  </div>
                ) : (
                  <div className="flex flex-1 flex-col items-center justify-center py-8 text-center text-xs text-slate-500">
                    <ImagePlus className="h-7 w-7 text-slate-300 mb-2" />
                    <p>No screenshot selected yet.</p>
                    <p className="mt-1">Try &ldquo;Load Sample Bank SMS&rdquo; above for an instant test.</p>
                  </div>
                )}

                <div className="space-y-3">
                  <input
                    type="text"
                    value={screenshotNote}
                    onChange={(e) => setScreenshotNote(e.target.value)}
                    placeholder="Optional note (e.g., Received via WhatsApp)"
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:outline-none"
                  />
                  <button
                    type="button"
                    disabled={isLoading || !screenshotDataUrl}
                    onClick={handleScanScreenshot}
                    className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-blue-700 px-5 py-3 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-50 transition-colors min-h-[44px] cursor-pointer"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Reading &amp; Analyzing...
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="h-4 w-4" />
                        Analyze Screenshot
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'url' && (
          <div className="space-y-5">
            <div>
              <h2 className="text-lg font-bold text-slate-900">Real-Time URL &amp; Phishing Link Scanner</h2>
              <p className="text-sm text-slate-500">
                Paste any suspicious website link. ScamShield checks DNS status, HTTPS encryption, redirects, and lookalike domain tricks without you ever opening the page.
              </p>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <input
                  type="url"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleScanUrl();
                  }}
                  placeholder="https://example.com/verify-account"
                  className="w-full rounded-xl border border-slate-300 bg-slate-50/60 py-3 pl-10 pr-4 font-mono text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-600/20 min-h-[44px]"
                />
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  disabled={isLoading}
                  onClick={() => handleScanUrl()}
                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-700 px-6 py-3 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors min-h-[44px] whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Inspecting Link...
                    </>
                  ) : (
                    <>
                      <Globe className="h-4 w-4" />
                      Check Link Safety
                    </>
                  )}
                </button>
                <button
                  type="button"
                  disabled={isLoading || !urlInput.trim()}
                  onClick={handleTestVisitUrl}
                  title="Simulate visiting this URL with ScamShield Safe Visit Guard"
                  className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-slate-300 bg-white px-4 py-3 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50 transition-colors min-h-[44px] whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  Safe Visit Guard
                </button>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium text-slate-500 mr-1">Test links:</span>
              {SAMPLE_URLS.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => {
                    setUrlInput(preset.url);
                    setErrorMsg(null);
                  }}
                  className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100 transition-colors min-h-[36px] cursor-pointer"
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {errorMsg && (
          <div
            role="alert"
            className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
          >
            {errorMsg}
          </div>
        )}
      </div>

      {/* Three-Step Beginner Explainer Strip */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-1.5">
          <div className="text-xs font-semibold text-blue-700">01. Paste or Upload Safely</div>
          <h3 className="text-sm font-bold text-slate-900">No need to click unknown links</h3>
          <p className="text-xs text-slate-600 leading-relaxed">
            Inspect screenshots, text messages, or URLs inside ScamShield before opening anything on your phone or browser.
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-1.5">
          <div className="text-xs font-semibold text-blue-700">02. See Exact Warning Signs</div>
          <h3 className="text-sm font-bold text-slate-900">Highlighted phrases &amp; reasons</h3>
          <p className="text-xs text-slate-600 leading-relaxed">
            Every urgency trick, fake brand domain, or gift-card demand is highlighted in context with a clear explanation.
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-1.5">
          <div className="text-xs font-semibold text-blue-700">03. Follow Calm Next Steps</div>
          <h3 className="text-sm font-bold text-slate-900">Actionable checklist &amp; recovery</h3>
          <p className="text-xs text-slate-600 leading-relaxed">
            Get step-by-step guidance on what to do next, and ask our Safety Assistant if you already clicked or replied.
          </p>
        </div>
      </div>
    </div>
  );
}
