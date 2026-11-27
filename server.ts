import 'dotenv/config';
import express from 'express';
import type { Request, Response } from 'express';
import dns from 'node:dns/promises';
import net from 'node:net';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { GoogleGenAI, Type } from '@google/genai';
import type { RiskLevel, ScanResult, SuspiciousPhrase, UrlCheckSignals } from './src/types/scam.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const MODEL_NAME = 'gemini-4-hydrogen';

function getAiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || !apiKey.trim()) {
    throw Object.assign(
      new Error('GEMINI_API_KEY is not configured. Please add your key in Settings > Secrets.'),
      { statusCode: 500 }
    );
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

// --- SSRF-Safe Real-Time URL Inspection Utilities ---

const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'click', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'support',
  'cam', 'loan', 'buzz', 'rest', 'fit', 'icu', 'shop', 'online', 'site',
]);

const ELEVATED_RISK_TLDS = new Set([
  'info', 'biz', 'cc', 'ws', 'me', 'co', 'io', 'club', 'vip', 'live',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'cutt.ly', 'rb.gy', 'shorturl.at', 'rebrand.ly', 'tiny.cc',
]);

const KNOWN_BRANDS = [
  'paypal', 'amazon', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
  'apple', 'icloud', 'microsoft', 'office365', 'netflix', 'google',
  'gmail', 'whatsapp', 'instagram', 'facebook', 'meta', 'coinbase',
  'binance', 'usps', 'fedex', 'dhl', 'ups', 'irs', 'hmrc', 'venmo', 'zelle',
  'stripe', 'shopify', 'steam', 'discord', 'tiktok',
];

const PHISHING_KEYWORDS = [
  'verify', 'login', 'signin', 'sign-in', 'secure', 'account', 'update',
  'suspend', 'suspended', 'locked', 'unlock', 'confirm', 'wallet',
  'claim', 'urgent', 'billing', 'password', 'security-alert', 'auth',
];

function isPrivateOrReservedIp(ip: string): boolean {
  const cleanIp = ip.replace(/^\[|\]$/g, '').split('%')[0];
  if (net.isIPv4(cleanIp)) {
    const parts = cleanIp.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return true;
    }
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }

  if (net.isIPv6(cleanIp)) {
    const lower = cleanIp.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
      return true; // link-local fe80::/10
    }
    if (lower.startsWith('::ffff:')) {
      const mapped = lower.slice(7);
      if (net.isIPv4(mapped)) return isPrivateOrReservedIp(mapped);
    }
    return false;
  }

  return true;
}

function detectLookalikeBrand(hostname: string): string | null {
  const lowerHost = hostname.toLowerCase();
  const normalizedLeet = lowerHost
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/rn/g, 'm');

  for (const brand of KNOWN_BRANDS) {
    // Official domain check (e.g., paypal.com or login.paypal.com)
    if (
      lowerHost === `${brand}.com` ||
      lowerHost.endsWith(`.${brand}.com`) ||
      lowerHost === `${brand}.org` ||
      lowerHost.endsWith(`.${brand}.org`) ||
      lowerHost === `${brand}.gov` ||
      lowerHost.endsWith(`.${brand}.gov`)
    ) {
      continue;
    }
    if (lowerHost.includes(brand) || normalizedLeet.includes(brand)) {
      return brand.charAt(0).toUpperCase() + brand.slice(1);
    }
  }
  return null;
}

async function inspectUrlSafely(rawInput: string): Promise<UrlCheckSignals> {
  let trimmed = rawInput.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = `https://${trimmed}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw Object.assign(new Error('Please enter a valid web link (for example, https://example.com).'), {
      statusCode: 400,
    });
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw Object.assign(new Error('Only http:// and https:// web links can be scanned.'), {
      statusCode: 400,
    });
  }

  const hostname = parsed.hostname.toLowerCase();
  const suspiciousPatterns: string[] = [];

  if (parsed.username || parsed.password) {
    suspiciousPatterns.push('Contains hidden login credentials (@ symbol trick) to disguise the real website.');
  }

  const isHttps = parsed.protocol === 'https:';
  if (!isHttps) {
    suspiciousPatterns.push('Uses unencrypted HTTP instead of secure HTTPS.');
  }

  const hasIpAddress = net.isIP(hostname.replace(/^\[|\]$/g, '')) !== 0;
  if (hasIpAddress) {
    suspiciousPatterns.push('Uses a raw IP address instead of a legitimate domain name.');
  }

  const hasPunycode = hostname.split('.').some((label) => label.startsWith('xn--'));
  if (hasPunycode) {
    suspiciousPatterns.push('Uses Punycode (xn--) characters, often used to imitate real brand letters.');
  }

  const labels = hostname.split('.').filter(Boolean);
  const tld = labels.length > 1 ? labels[labels.length - 1] : '';
  let tldRisk: 'standard' | 'elevated' | 'high' = 'standard';
  if (HIGH_RISK_TLDS.has(tld)) {
    tldRisk = 'high';
    suspiciousPatterns.push(`Uses a ".${tld}" domain ending frequently abused in temporary scam campaigns.`);
  } else if (ELEVATED_RISK_TLDS.has(tld)) {
    tldRisk = 'elevated';
  }

  if (labels.length >= 4 && !hasIpAddress) {
    suspiciousPatterns.push(`Unusually long chain of ${labels.length} domain levels used to hide the true destination.`);
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    suspiciousPatterns.push(`Domain contains ${hyphenCount} hyphens, a common pattern in fake login pages.`);
  }

  const isShortener = URL_SHORTENERS.has(hostname);
  if (isShortener) {
    suspiciousPatterns.push('Shortened link hides the real destination website.');
  }

  const lookalikeBrand = detectLookalikeBrand(hostname);
  if (lookalikeBrand) {
    suspiciousPatterns.push(`Mentions "${lookalikeBrand}" in an unofficial domain name.`);
  }

  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const matchedKeywords = PHISHING_KEYWORDS.filter((kw) => pathAndQuery.includes(kw) || hostname.includes(kw));
  if (matchedKeywords.length > 0) {
    suspiciousPatterns.push(`Contains high-risk account/action keywords (${matchedKeywords.slice(0, 4).join(', ')}).`);
  }

  // Strip embedded credentials before constructing outbound probe URL
  const safeUrlObj = new URL(parsed.toString());
  safeUrlObj.username = '';
  safeUrlObj.password = '';
  const normalizedUrl = safeUrlObj.toString();

  // Block private/internal hostnames immediately (SSRF safeguard)
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.localhost') ||
    (hasIpAddress && isPrivateOrReservedIp(hostname))
  ) {
    return {
      normalizedUrl,
      hostname,
      protocol: parsed.protocol.replace(':', ''),
      isHttps,
      dnsResolved: false,
      resolvedIpsCount: 0,
      httpStatus: null,
      finalUrl: null,
      redirected: false,
      suspiciousPatterns: [
        ...suspiciousPatterns,
        'Points to a private or local network address, blocked for safety.',
      ],
      tldRisk,
      lookalikeBrand,
      isShortener,
      hasIpAddress,
      hasPunycode,
      blockedReason: 'Private or local network host blocked from live network probe.',
    };
  }

  let dnsResolved = false;
  let resolvedIpsCount = 0;
  let httpStatus: number | null = null;
  let finalUrl: string | null = null;
  let redirected = false;
  let blockedReason: string | null = null;

  try {
    const records = await Promise.race([
      dns.lookup(hostname, { all: true }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), 2500)),
    ]);

    if (records.length > 0) {
      const hasPrivateTarget = records.some((r) => isPrivateOrReservedIp(r.address));
      if (hasPrivateTarget) {
        blockedReason = 'Domain resolves to a private or reserved network address.';
        suspiciousPatterns.push('Domain resolves to an internal/reserved IP address.');
      } else {
        dnsResolved = true;
        resolvedIpsCount = records.length;
      }
    }
  } catch {
    dnsResolved = false;
  }

  if (dnsResolved && !blockedReason) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3000);
      const probeRes = await fetch(normalizedUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'ScamShield-SafetyInspector/1.0',
        },
      });
      clearTimeout(timer);
      httpStatus = probeRes.status;
      if (probeRes.status >= 300 && probeRes.status < 400) {
        redirected = true;
        const loc = probeRes.headers.get('location');
        if (loc) {
          try {
            const target = new URL(loc, normalizedUrl);
            finalUrl = target.toString();
            if (target.hostname.toLowerCase() !== hostname) {
              suspiciousPatterns.push(`Redirects visitors to a different domain (${target.hostname}).`);
            }
          } catch {
            finalUrl = null;
          }
        }
      }
    } catch {
      // Live probe timed out or refused; keep DNS + lexical signals
    }
  }

  return {
    normalizedUrl,
    hostname,
    protocol: parsed.protocol.replace(':', ''),
    isHttps,
    dnsResolved,
    resolvedIpsCount,
    httpStatus,
    finalUrl,
    redirected,
    suspiciousPatterns,
    tldRisk,
    lookalikeBrand,
    isShortener,
    hasIpAddress,
    hasPunycode,
    blockedReason,
  };
}

function extractFirstUrlFromText(text: string): string | null {
  const match = text.match(/https?:\/\/[^\s"'<>()]+/i);
  if (match) return match[0].replace(/[.,;!?]+$/, '');
  const bareMatch = text.match(/\b(?:[a-z0-9-]+\.)+(?:com|net|org|xyz|top|click|info|io|co|biz|tk|ml|ga|cf|gq)\b(?:\/[^\s"'<>()]*)?/i);
  if (bareMatch) return `https://${bareMatch[0].replace(/[.,;!?]+$/, '')}`;
  return null;
}

const scanAnalysisSchema = {
  type: Type.OBJECT,
  properties: {
    riskLevel: {
      type: Type.STRING,
      description: 'Must be exactly one of: Low, Medium, High',
    },
    scamCategory: {
      type: Type.STRING,
      description: 'Short plain-English category e.g. Bank Impersonation, Job Offer Scam, Delivery Phishing, Tech Support Scam, Safe Communication',
    },
    headline: {
      type: Type.STRING,
      description: 'Calm, clear 6-12 word headline summarizing the verdict for a beginner.',
    },
    beginnerSummary: {
      type: Type.STRING,
      description: 'One reassuring, crystal-clear sentence in everyday language telling the user what this is and the first thing to do.',
    },
    plainExplanation: {
      type: Type.STRING,
      description: '2-4 short, jargon-free sentences explaining why this looks suspicious or safe.',
    },
    extractedText: {
      type: Type.STRING,
      description: 'For screenshots: exact verbatim text read from the image. For text/URL scans: the exact input text.',
    },
    suspiciousPhrases: {
      type: Type.ARRAY,
      description: 'Exact verbatim substrings copied directly from extractedText that show red flags (empty array if Low risk and no red flags).',
      items: {
        type: Type.OBJECT,
        properties: {
          phrase: {
            type: Type.STRING,
            description: 'Exact substring copied verbatim from extractedText so it can be highlighted.',
          },
          tactic: {
            type: Type.STRING,
            description: 'Short label like Artificial Urgency, Fake Link, Gift Card Request, Impersonation, Threat of Account Freeze.',
          },
          reason: {
            type: Type.STRING,
            description: 'Simple 1-sentence explanation of why this phrase is a warning sign.',
          },
          severity: {
            type: Type.STRING,
            description: 'One of: low, medium, high',
          },
        },
        required: ['phrase', 'tactic', 'reason', 'severity'],
      },
    },
    safetySteps: {
      type: Type.ARRAY,
      description: '3 to 5 practical, numbered-style next steps written for a beginner.',
      items: { type: Type.STRING },
    },
    doNotDo: {
      type: Type.ARRAY,
      description: '2 to 4 clear warnings of actions the user must avoid right now.',
      items: { type: Type.STRING },
    },
    urgentHelpNote: {
      type: Type.STRING,
      description: 'Helpful recovery guidance if the user already clicked or replied (e.g., contacting bank via official card number).',
    },
  },
  required: [
    'riskLevel',
    'scamCategory',
    'headline',
    'beginnerSummary',
    'plainExplanation',
    'extractedText',
    'suspiciousPhrases',
    'safetySteps',
    'doNotDo',
  ],
};

function normalizeRiskLevel(val: unknown): RiskLevel {
  if (typeof val === 'string') {
    const lower = val.toLowerCase();
    if (lower.includes('high')) return 'High';
    if (lower.includes('medium')) return 'Medium';
  }
  return 'Low';
}

function sanitizePhrases(raw: unknown): SuspiciousPhrase[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
    .map((item) => {
      const sev = String(item.severity || 'medium').toLowerCase();
      return {
        phrase: String(item.phrase || '').trim(),
        tactic: String(item.tactic || 'Warning Sign').trim(),
        reason: String(item.reason || '').trim(),
        severity: (sev === 'high' || sev === 'low' ? sev : 'medium') as 'low' | 'medium' | 'high',
      };
    })
    .filter((p) => p.phrase.length > 0);
}

async function generateWithRetry(
  ai: GoogleGenAI,
  params: Parameters<GoogleGenAI['models']['generateContent']>[0],
  maxAttempts = 3
) {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await ai.models.generateContent(params);
    } catch (err) {
      lastErr = err;
      const errObj = err as { status?: number; statusCode?: number; message?: string };
      const msg = String(errObj?.message || '');
      const status = errObj?.status || errObj?.statusCode;
      const isTransient = status === 503 || status === 429 || msg.includes('"code":503') || msg.includes('UNAVAILABLE');
      if (!isTransient || attempt === maxAttempts) {
        throw err;
      }
      const delayMs = 600 * Math.pow(2, attempt - 1);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw lastErr;
}

function handleApiError(err: unknown, res: Response) {
  const errorObj = err as { statusCode?: number; status?: number; message?: string };
  let status = errorObj?.statusCode || errorObj?.status || 500;
  let message = errorObj?.message || 'Unable to complete the scan right now. Please try again.';

  // Unwrap nested JSON error messages from upstream SDK responses
  if (message.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(message) as { error?: { code?: number; message?: string; status?: string } };
      if (parsed?.error?.code) status = parsed.error.code;
      if (parsed?.error?.message) message = parsed.error.message;
    } catch {
      // Keep original string if not valid JSON
    }
  }

  if (status === 503) {
    message = 'The AI scanner is experiencing a brief surge in demand. Please click scan again in a moment.';
  } else if (status === 403 || message.includes('API_KEY_INVALID') || message.includes('PERMISSION_DENIED')) {
    message = 'AI service credentials need attention. Please verify your Gemini API key in Settings > Secrets.';
  } else if (status === 429 || message.includes('RESOURCE_EXHAUSTED')) {
    message = 'AI request limit reached temporarily. Please wait a moment and try again.';
  }

  console.error('[ScamShield API Error]', status, message);
  res.status(status >= 400 && status < 600 ? status : 500).json({ error: message });
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '12mb' }));

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ ok: true });
  });

  // 1. Smart Message Scanner (SMS, WhatsApp, Email)
  app.post('/api/scan/message', async (req: Request, res: Response) => {
    try {
      const { message, sourceType } = req.body as { message?: string; sourceType?: string };
      if (!message || typeof message !== 'string' || message.trim().length < 5) {
        res.status(400).json({ error: 'Please paste a message of at least 5 characters to scan.' });
        return;
      }
      const cleanMessage = message.trim().slice(0, 8000);
      const channelHint = typeof sourceType === 'string' ? sourceType : 'message';

      const detectedUrl = extractFirstUrlFromText(cleanMessage);
      let urlSignals: UrlCheckSignals | null = null;
      if (detectedUrl) {
        try {
          urlSignals = await inspectUrlSafely(detectedUrl);
        } catch {
          urlSignals = null;
        }
      }

      const ai = getAiClient();
      const prompt = `Analyze the following ${channelHint} for scams, phishing, impersonation, or fraud.
Audience: A non-technical everyday user or potential scam victim who needs calm, plain-English guidance.

Message text:
"""
${cleanMessage}
"""

${urlSignals ? `Automated Real-Time URL Check on link inside message (${urlSignals.normalizedUrl}):
- HTTPS: ${urlSignals.isHttps}
- DNS Resolved: ${urlSignals.dnsResolved}
- Redirected: ${urlSignals.redirected}
- Suspicious URL patterns detected: ${urlSignals.suspiciousPatterns.join('; ') || 'None'}` : ''}

Instructions:
1. Classify riskLevel strictly as "Low", "Medium", or "High".
2. Copy extractedText verbatim as the exact message text above.
3. For suspiciousPhrases, copy EXACT substrings verbatim from the message text above (exact casing/punctuation) so the UI can highlight them inline.
4. Keep explanations empathetic, crystal clear, and free of technical jargon.`;

      const response = await generateWithRetry(ai, {
        model: MODEL_NAME,
        contents: prompt,
        config: {
          systemInstruction:
            'You are ScamShield AI, a calm, trustworthy digital safety advisor helping everyday people detect online scams and understand what to do next.',
          responseMimeType: 'application/json',
          responseSchema: scanAnalysisSchema,
        },
      });

      const parsed = JSON.parse((response.text || '{}').trim());
      const result: ScanResult = {
        id: `scan_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
        createdAt: new Date().toISOString(),
        channel: 'message',
        inputSummary: cleanMessage.slice(0, 120) + (cleanMessage.length > 120 ? '...' : ''),
        extractedText: cleanMessage,
        riskLevel: normalizeRiskLevel(parsed.riskLevel),
        scamCategory: String(parsed.scamCategory || 'Message Analysis'),
        headline: String(parsed.headline || 'Scan completed'),
        beginnerSummary: String(parsed.beginnerSummary || ''),
        plainExplanation: String(parsed.plainExplanation || ''),
        suspiciousPhrases: sanitizePhrases(parsed.suspiciousPhrases),
        urlAnalysis: urlSignals,
        safetySteps: Array.isArray(parsed.safetySteps) ? parsed.safetySteps.map(String) : [],
        doNotDo: Array.isArray(parsed.doNotDo) ? parsed.doNotDo.map(String) : [],
        urgentHelpNote: parsed.urgentHelpNote ? String(parsed.urgentHelpNote) : undefined,
      };

      res.json(result);
    } catch (err) {
      handleApiError(err, res);
    }
  });

  // 2. Screenshot Analysis (Multimodal Image Understanding)
  app.post('/api/scan/screenshot', async (req: Request, res: Response) => {
    try {
      const { imageBase64, mimeType, contextNote } = req.body as {
        imageBase64?: string;
        mimeType?: string;
        contextNote?: string;
      };

      const allowedMimeTypes = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/gif']);
      if (!imageBase64 || typeof imageBase64 !== 'string') {
        res.status(400).json({ error: 'Please upload a screenshot image to analyze.' });
        return;
      }
      const cleanMime = typeof mimeType === 'string' && allowedMimeTypes.has(mimeType.toLowerCase())
        ? mimeType.toLowerCase() === 'image/jpg'
          ? 'image/jpeg'
          : mimeType.toLowerCase()
        : 'image/png';

      // Strip data URL prefix if accidentally included
      const base64Data = imageBase64.includes(',') ? imageBase64.split(',')[1] : imageBase64;
      if (base64Data.length > 14_000_000) {
        res.status(400).json({ error: 'Image is too large. Please upload a screenshot under 10 MB.' });
        return;
      }

      const ai = getAiClient();
      const noteText = typeof contextNote === 'string' && contextNote.trim()
        ? `User note: ${contextNote.trim().slice(0, 500)}`
        : '';

      const response = await generateWithRetry(ai, {
        model: MODEL_NAME,
        contents: {
          parts: [
            {
              inlineData: {
                mimeType: cleanMime,
                data: base64Data,
              },
            },
            {
              text: `Read all text visible in this screenshot of a message, email, or webpage, and evaluate whether it is a scam, phishing attempt, or safe.
${noteText}

Instructions:
1. Put the exact, complete text you read from the screenshot into extractedText.
2. Classify riskLevel strictly as "Low", "Medium", or "High".
3. For suspiciousPhrases, copy EXACT substrings verbatim from extractedText so they can be highlighted directly in the extracted text view.
4. Explain the warning signs and next steps in warm, simple language anyone can follow.`,
            },
          ],
        },
        config: {
          systemInstruction:
            'You are ScamShield AI, an expert at reading screenshots of suspicious messages and explaining fraud signs clearly to everyday people.',
          responseMimeType: 'application/json',
          responseSchema: scanAnalysisSchema,
        },
      });

      const parsed = JSON.parse((response.text || '{}').trim());
      const extractedText = String(parsed.extractedText || '').trim() || 'Text extracted from uploaded screenshot.';

      const detectedUrl = extractFirstUrlFromText(extractedText);
      let urlSignals: UrlCheckSignals | null = null;
      if (detectedUrl) {
        try {
          urlSignals = await inspectUrlSafely(detectedUrl);
        } catch {
          urlSignals = null;
        }
      }

      const result: ScanResult = {
        id: `scan_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
        createdAt: new Date().toISOString(),
        channel: 'screenshot',
        inputSummary: extractedText.slice(0, 120) + (extractedText.length > 120 ? '...' : ''),
        extractedText,
        riskLevel: normalizeRiskLevel(parsed.riskLevel),
        scamCategory: String(parsed.scamCategory || 'Screenshot Analysis'),
        headline: String(parsed.headline || 'Screenshot analyzed'),
        beginnerSummary: String(parsed.beginnerSummary || ''),
        plainExplanation: String(parsed.plainExplanation || ''),
        suspiciousPhrases: sanitizePhrases(parsed.suspiciousPhrases),
        urlAnalysis: urlSignals,
        safetySteps: Array.isArray(parsed.safetySteps) ? parsed.safetySteps.map(String) : [],
        doNotDo: Array.isArray(parsed.doNotDo) ? parsed.doNotDo.map(String) : [],
        urgentHelpNote: parsed.urgentHelpNote ? String(parsed.urgentHelpNote) : undefined,
      };

      res.json(result);
    } catch (err) {
      handleApiError(err, res);
    }
  });

  // 3. Real-Time URL Scanner & Fake Link Detection
  app.post('/api/scan/url', async (req: Request, res: Response) => {
    try {
      const { url } = req.body as { url?: string };
      if (!url || typeof url !== 'string' || url.trim().length < 3) {
        res.status(400).json({ error: 'Please enter a website link (URL) to check.' });
        return;
      }

      const urlSignals = await inspectUrlSafely(url);
      const ai = getAiClient();

      const prompt = `Evaluate this website URL for phishing, impersonation, or scam risk based on the real-time technical signals gathered below.

URL submitted: ${urlSignals.normalizedUrl}
Real-time inspection findings:
- Domain hostname: ${urlSignals.hostname}
- Uses HTTPS encryption: ${urlSignals.isHttps ? 'Yes' : 'No (HTTP only)'}
- DNS resolves to active public server: ${urlSignals.dnsResolved ? `Yes (${urlSignals.resolvedIpsCount} record(s))` : 'No (domain is unregistered, offline, or blocked)'}
- HTTP probe status: ${urlSignals.httpStatus ?? 'Not reachable / skipped'}
- Redirected: ${urlSignals.redirected ? `Yes -> ${urlSignals.finalUrl}` : 'No'}
- Lookalike brand detected: ${urlSignals.lookalikeBrand || 'None'}
- URL shortener: ${urlSignals.isShortener ? 'Yes' : 'No'}
- IP address instead of domain: ${urlSignals.hasIpAddress ? 'Yes' : 'No'}
- Punycode homograph characters: ${urlSignals.hasPunycode ? 'Yes' : 'No'}
- Top-level domain risk tier: ${urlSignals.tldRisk}
- Automated pattern flags: ${urlSignals.suspiciousPatterns.length > 0 ? urlSignals.suspiciousPatterns.join(' | ') : 'None detected'}

Instructions:
1. Set extractedText strictly to "${urlSignals.normalizedUrl}".
2. Set suspiciousPhrases to exact substrings inside "${urlSignals.normalizedUrl}" that look suspicious (such as the fake domain segment, risky TLD, or "verify-login" path). If the URL is a well-known legitimate official site with no red flags, keep suspiciousPhrases empty.
3. Classify riskLevel as "Low", "Medium", or "High".
4. Explain what the link is doing in simple, non-technical language.`;

      const response = await generateWithRetry(ai, {
        model: MODEL_NAME,
        contents: prompt,
        config: {
          systemInstruction:
            'You are ScamShield AI, helping everyday users spot fake links, lookalike websites, and phishing URLs before they click.',
          responseMimeType: 'application/json',
          responseSchema: scanAnalysisSchema,
        },
      });

      const parsed = JSON.parse((response.text || '{}').trim());
      const result: ScanResult = {
        id: `scan_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
        createdAt: new Date().toISOString(),
        channel: 'url',
        inputSummary: urlSignals.normalizedUrl,
        extractedText: urlSignals.normalizedUrl,
        riskLevel: normalizeRiskLevel(parsed.riskLevel),
        scamCategory: String(parsed.scamCategory || 'Link Safety Check'),
        headline: String(parsed.headline || 'URL inspection complete'),
        beginnerSummary: String(parsed.beginnerSummary || ''),
        plainExplanation: String(parsed.plainExplanation || ''),
        suspiciousPhrases: sanitizePhrases(parsed.suspiciousPhrases),
        urlAnalysis: urlSignals,
        safetySteps: Array.isArray(parsed.safetySteps) ? parsed.safetySteps.map(String) : [],
        doNotDo: Array.isArray(parsed.doNotDo) ? parsed.doNotDo.map(String) : [],
        urgentHelpNote: parsed.urgentHelpNote ? String(parsed.urgentHelpNote) : undefined,
      };

      res.json(result);
    } catch (err) {
      handleApiError(err, res);
    }
  });

  // 4. AI Safety Assistant Chatbot
  app.post('/api/chat', async (req: Request, res: Response) => {
    try {
      const { messages, activeScanContext } = req.body as {
        messages?: Array<{ role: 'user' | 'assistant'; content: string }>;
        activeScanContext?: {
          channel?: string;
          riskLevel?: string;
          scamCategory?: string;
          headline?: string;
          extractedText?: string;
        } | null;
      };

      if (!Array.isArray(messages) || messages.length === 0) {
        res.status(400).json({ error: 'Please type a question to ask the safety assistant.' });
        return;
      }

      const recentMessages = messages.slice(-12);
      const latestUserMessage = recentMessages[recentMessages.length - 1]?.content;
      if (!latestUserMessage || typeof latestUserMessage !== 'string') {
        res.status(400).json({ error: 'Message content is required.' });
        return;
      }

      const conversationHistory = recentMessages
        .slice(0, -1)
        .map((m) => `${m.role === 'user' ? 'User' : 'Assistant'}: ${String(m.content).slice(0, 1500)}`)
        .join('\n');

      const scanContextBlock = activeScanContext
        ? `\nContext from user's most recent ScamShield scan:\n- Channel: ${activeScanContext.channel}\n- Risk Level: ${activeScanContext.riskLevel}\n- Category: ${activeScanContext.scamCategory}\n- Summary: ${activeScanContext.headline}\n- Scanned Content: ${String(activeScanContext.extractedText || '').slice(0, 800)}\n`
        : '';

      const ai = getAiClient();
      const fullPrompt = `${scanContextBlock}${conversationHistory ? `Conversation so far:\n${conversationHistory}\n\n` : ''}User: ${latestUserMessage.slice(0, 2000)}`;

      const response = await generateWithRetry(ai, {
        model: MODEL_NAME,
        contents: fullPrompt,
        config: {
          systemInstruction:
            'You are the ScamShield AI Safety Assistant. Help beginners, seniors, and potential scam victims stay calm and safe. Use plain, empathetic, step-by-step advice. Never judge the user if they already clicked a link or sent money—give immediate practical recovery steps (freezing cards using the number on the back of their card, changing passwords, enabling 2FA, reporting fraud). Keep responses concise, structured with short bullet points, and easy to scan.',
        },
      });

      res.json({
        reply: response.text || 'I am here to help. Could you share a bit more detail about what happened?',
      });
    } catch (err) {
      handleApiError(err, res);
    }
  });

  // 5. Localized Regional Threat Advisory (Gemini 4 Hydrogen)
  app.post('/api/threats/advisory', async (req: Request, res: Response) => {
    try {
      const { regionName, scamLabel, localExample } = req.body as {
        regionName?: string;
        scamLabel?: string;
        localExample?: string;
      };

      if (!regionName || typeof regionName !== 'string' || !scamLabel || typeof scamLabel !== 'string') {
        res.status(400).json({ error: 'Region and scam type are required.' });
        return;
      }

      const cleanRegion = regionName.trim().slice(0, 80);
      const cleanScam = scamLabel.trim().slice(0, 80);
      const cleanExample = typeof localExample === 'string' ? localExample.trim().slice(0, 400) : '';

      const ai = getAiClient();
      const response = await generateWithRetry(ai, {
        model: MODEL_NAME,
        contents: `Provide a concise, beginner-friendly local threat advisory for people in ${cleanRegion} facing "${cleanScam}" scams right now.
${cleanExample ? `Example circulating locally: "${cleanExample}"` : ''}

Include:
1. Why scammers target people in ${cleanRegion} with this exact tactic (2 short sentences).
2. 3 specific local warning signs to check before clicking or paying.
3. Official local place to verify or report fraud in ${cleanRegion} (in plain language).`,
        config: {
          systemInstruction:
            'You are ScamShield AI, providing calm, accurate, region-specific fraud awareness for everyday people. Keep it under 150 words, plain language, and immediately actionable.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: { type: Type.STRING },
              localSigns: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
              whereToReport: { type: Type.STRING },
            },
            required: ['summary', 'localSigns', 'whereToReport'],
          },
        },
      });

      const parsed = JSON.parse((response.text || '{}').trim());
      res.json({
        summary: String(parsed.summary || ''),
        localSigns: Array.isArray(parsed.localSigns) ? parsed.localSigns.map(String) : [],
        whereToReport: String(parsed.whereToReport || ''),
      });
    } catch (err) {
      handleApiError(err, res);
    }
  });

  // Vite dev middleware or production static build
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req: Request, res: Response) => {
      const indexFile = path.join(distDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Build output not found. Run npm run build first.');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ScamShield AI server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start ScamShield AI server:', err);
  process.exit(1);
});
