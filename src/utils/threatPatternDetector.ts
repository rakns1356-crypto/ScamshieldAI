export interface LiveThreatMatch {
  triggerKey: string;
  severity: 'high' | 'medium';
  category: 'high-risk-url' | 'malicious-pattern';
  title: string;
  summary: string;
  matchedPattern: string;
  recommendations: string[];
}

const KNOWN_BRANDS = [
  'paypal', 'amazon', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
  'apple', 'icloud', 'microsoft', 'netflix', 'google', 'whatsapp',
  'coinbase', 'binance', 'usps', 'fedex', 'dhl', 'ups', 'irs', 'hmrc',
  'venmo', 'zelle', 'revolut', 'auspost',
];

const HIGH_RISK_TLDS = [
  'xyz', 'top', 'click', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'support',
  'cam', 'loan', 'buzz', 'icu',
];

const AUTH_KEYWORDS = [
  'verify', 'login', 'signin', 'sign-in', 'secure', 'suspend', 'suspended',
  'unlock', 'update-billing', 'billing', 'auth', 'confirm', 'wallet',
];

function extractUrlCandidate(text: string): string | null {
  const fullMatch = text.match(/https?:\/\/[^\s"'<>()]+/i);
  if (fullMatch) return fullMatch[0].replace(/[.,;!?]+$/, '');
  const hostMatch = text.match(
    /\b(?:[a-z0-9-]+\.)+(?:com|net|org|xyz|top|click|info|io|co|biz|tk|ml|ga|cf|gq|work|support)\b(?:\/[^\s"'<>()]*)?/i
  );
  if (hostMatch) return `https://${hostMatch[0].replace(/[.,;!?]+$/, '')}`;
  return null;
}

export function detectHighRiskUrl(rawUrl: string): LiveThreatMatch | null {
  const trimmed = rawUrl.trim();
  if (trimmed.length < 4) return null;

  let normalized = trimmed;
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = `https://${normalized}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return null;
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullLower = parsed.toString().toLowerCase();
  const labels = hostname.split('.').filter(Boolean);
  const tld = labels.length > 1 ? labels[labels.length - 1] : '';

  // 1. Credential @ symbol obfuscation
  if (parsed.username || parsed.password) {
    return {
      triggerKey: `url-at-${hostname}`,
      severity: 'high',
      category: 'high-risk-url',
      title: 'High-Risk URL Blocked: Hidden Redirect Trap',
      summary: 'This link uses an "@" symbol trick to hide the real website you would actually visit.',
      matchedPattern: trimmed.slice(0, 80),
      recommendations: [
        'Do not open this link or enter any login details.',
        'Open the official website directly by typing it yourself.',
      ],
    };
  }

  // 2. Raw IP literal URL
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return {
      triggerKey: `url-ip-${hostname}`,
      severity: 'high',
      category: 'high-risk-url',
      title: 'High-Risk URL Detected: Raw IP Web Address',
      summary: 'Legitimate banks and services use official domain names, not raw numeric IP addresses.',
      matchedPattern: hostname,
      recommendations: [
        'Avoid opening links that point directly to an IP address.',
        'Run a full URL Check to inspect the destination safely.',
      ],
    };
  }

  // 3. Punycode homograph attack
  if (hostname.includes('xn--')) {
    return {
      triggerKey: `url-puny-${hostname}`,
      severity: 'high',
      category: 'high-risk-url',
      title: 'High-Risk URL Detected: Lookalike Character Trick',
      summary: 'This domain uses hidden Punycode characters often used to impersonate trusted brands.',
      matchedPattern: hostname,
      recommendations: [
        'Do not trust or click this link.',
        'Verify the service using its official mobile app instead.',
      ],
    };
  }

  // 4. Lookalike brand detection (with leet-speak normalization)
  const leetNormalized = hostname
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/rn/g, 'm');

  const impersonatedBrand = KNOWN_BRANDS.find((brand) => {
    const isOfficial =
      hostname === `${brand}.com` ||
      hostname.endsWith(`.${brand}.com`) ||
      hostname === `${brand}.org` ||
      hostname.endsWith(`.${brand}.org`) ||
      hostname === `${brand}.gov` ||
      hostname.endsWith(`.${brand}.gov`);
    if (isOfficial) return false;
    return hostname.includes(brand) || leetNormalized.includes(brand);
  });

  const hasHighRiskTld = HIGH_RISK_TLDS.includes(tld);
  const hasAuthKeyword = AUTH_KEYWORDS.some((kw) => fullLower.includes(kw));

  if (impersonatedBrand) {
    const brandName = impersonatedBrand.charAt(0).toUpperCase() + impersonatedBrand.slice(1);
    return {
      triggerKey: `url-brand-${hostname}`,
      severity: 'high',
      category: 'high-risk-url',
      title: `High-Risk URL: Fake ${brandName} Impersonation`,
      summary: `This link mentions "${brandName}" on an unofficial domain (${hostname}).`,
      matchedPattern: hostname,
      recommendations: [
        `Do not sign in—this is not the official ${brandName} website.`,
        'Visit the real service by opening your saved bookmark or official app.',
        'Click Check Link Safety for full DNS and redirect details.',
      ],
    };
  }

  if (hasHighRiskTld && hasAuthKeyword) {
    return {
      triggerKey: `url-tld-${hostname}`,
      severity: 'high',
      category: 'high-risk-url',
      title: 'High-Risk URL Pattern Detected',
      summary: `Combines a disposable ".${tld}" domain with account-login keywords.`,
      matchedPattern: hostname,
      recommendations: [
        'Never type passwords or card numbers on unfamiliar ".xyz" or ".top" links.',
        'Run Check Link Safety before taking any action.',
      ],
    };
  }

  if (parsed.protocol === 'http:' && hasAuthKeyword) {
    return {
      triggerKey: `url-http-${hostname}`,
      severity: 'medium',
      category: 'high-risk-url',
      title: 'Caution: Unencrypted Login Link',
      summary: 'This link uses insecure HTTP while asking for account verification or billing updates.',
      matchedPattern: hostname,
      recommendations: [
        'Avoid entering passwords or payment cards on unencrypted HTTP pages.',
        'Verify whether the sender is genuine using the official app.',
      ],
    };
  }

  return null;
}

export function detectMaliciousMessagePattern(text: string): LiveThreatMatch | null {
  const clean = text.trim();
  if (clean.length < 12) return null;

  // Check if message contains a high-risk URL first
  const embeddedUrl = extractUrlCandidate(clean);
  if (embeddedUrl) {
    const urlAlert = detectHighRiskUrl(embeddedUrl);
    if (urlAlert && urlAlert.severity === 'high') {
      return {
        ...urlAlert,
        triggerKey: `msg-${urlAlert.triggerKey}`,
        title: 'Malicious Link Found in Message',
      };
    }
  }

  const lower = clean.toLowerCase();

  // Pattern 1: Gift card / Telegram / crypto payment demand
  const giftCardMatch = lower.match(
    /(apple gift card|google play card|steam card|gift card.*fee|refundable.*fee|telegram @|whatsapp.*fee)/i
  );
  if (giftCardMatch) {
    return {
      triggerKey: `msg-giftcard-${giftCardMatch[0]}`,
      severity: 'high',
      category: 'malicious-pattern',
      title: 'Known Scam Pattern: Upfront Gift Card or Fee Demand',
      summary: 'Real employers, banks, and government agencies never ask for gift cards or upfront fees to unlock pay or verify accounts.',
      matchedPattern: giftCardMatch[0],
      recommendations: [
        'Stop communicating with this sender immediately.',
        'Never buy gift cards or send money to claim a job or prize.',
      ],
    };
  }

  // Pattern 2: Account freeze / urgent countdown threat
  const urgencyMatch = lower.match(
    /(permanently suspended|funds will be.*frozen|within 2 hours|within 24 hours|avoid account closure|power will be disconnected|unpaid toll.*midnight)/i
  );
  if (urgencyMatch) {
    return {
      triggerKey: `msg-urgency-${urgencyMatch[0]}`,
      severity: 'high',
      category: 'malicious-pattern',
      title: 'Known Phishing Pattern: Urgent Freeze Threat',
      summary: 'Scammers use fake countdowns and threats to make you panic and click before checking.',
      matchedPattern: urgencyMatch[0],
      recommendations: [
        'Do not tap any links or reply to this message.',
        'Call the number on the back of your card or check your official app.',
      ],
    };
  }

  // Pattern 3: OTP / PIN / QR code theft
  const otpMatch = lower.match(
    /(share.*otp|read.*6-digit|enter your upi pin|scan.*qr.*receive|verification code.*confirm)/i
  );
  if (otpMatch) {
    return {
      triggerKey: `msg-otp-${otpMatch[0]}`,
      severity: 'high',
      category: 'malicious-pattern',
      title: 'Known Fraud Pattern: Passcode / PIN Harvesting',
      summary: 'One-time passcodes and UPI PINs are only for your own sign-ins or sending money—never to receive refunds.',
      matchedPattern: otpMatch[0],
      recommendations: [
        'Never share 6-digit login codes or PINs with anyone.',
        'Block the sender and run Scan Message for full analysis.',
      ],
    };
  }

  return null;
}
