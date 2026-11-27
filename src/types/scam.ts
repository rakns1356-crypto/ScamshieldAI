export type RiskLevel = 'Low' | 'Medium' | 'High';

export type ScanChannel = 'message' | 'screenshot' | 'url';

export interface SuspiciousPhrase {
  phrase: string;
  reason: string;
  tactic: string;
  severity: 'low' | 'medium' | 'high';
}

export interface UrlCheckSignals {
  normalizedUrl: string;
  hostname: string;
  protocol: string;
  isHttps: boolean;
  dnsResolved: boolean;
  resolvedIpsCount: number;
  httpStatus: number | null;
  finalUrl: string | null;
  redirected: boolean;
  suspiciousPatterns: string[];
  tldRisk: 'standard' | 'elevated' | 'high';
  lookalikeBrand: string | null;
  isShortener: boolean;
  hasIpAddress: boolean;
  hasPunycode: boolean;
  blockedReason?: string | null;
}

export interface ScanResult {
  id: string;
  createdAt: string;
  channel: ScanChannel;
  inputSummary: string;
  extractedText: string;
  imagePreviewDataUrl?: string;
  riskLevel: RiskLevel;
  scamCategory: string;
  headline: string;
  plainExplanation: string;
  beginnerSummary: string;
  suspiciousPhrases: SuspiciousPhrase[];
  urlAnalysis?: UrlCheckSignals | null;
  safetySteps: string[];
  doNotDo: string[];
  urgentHelpNote?: string;
  isSample?: boolean;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}
