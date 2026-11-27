import type { ScanResult } from '../types/scam';

export const SAMPLE_JOB_CHAT_IMAGE = '/src/assets/images/sample_job_scam_chat_1795708908180.jpg';

export interface SampleMessagePreset {
  id: string;
  label: string;
  sourceType: 'SMS' | 'WhatsApp' | 'Email';
  text: string;
}

export const SAMPLE_MESSAGES: SampleMessagePreset[] = [
  {
    id: 'bank_sms',
    label: 'Suspicious Bank Alert SMS',
    sourceType: 'SMS',
    text: 'CHASE-ALERT: Unusual sign-in detected on your checking account. Your debit card has been temporarily frozen. Verify your identity within 2 hours at http://chase-verify-secure.xyz/login or your account will be permanently suspended.',
  },
  {
    id: 'delivery_sms',
    label: 'Fake Package Delivery Fee',
    sourceType: 'SMS',
    text: 'USPS Notice: Your package #US948271 cannot be delivered due to an incomplete street address. Update your details and pay a $2.95 redelivery fee today at https://usps-track-redelivery.top/confirm to avoid return.',
  },
  {
    id: 'job_whatsapp',
    label: 'Remote Job Gift Card Scam',
    sourceType: 'WhatsApp',
    text: 'Hello! I am Sarah from Global Talent HR. We reviewed your resume for a $420/day remote data entry role (no experience needed). Please send a $45 refundable onboarding fee via Apple Gift Card to our Telegram manager @hr_onboarding_desk to start today!',
  },
  {
    id: 'safe_receipt',
    label: 'Safe Official Appointment Text',
    sourceType: 'SMS',
    text: 'Reminder from Oakridge Family Dental: Your cleaning appointment with Dr. Patel is scheduled for Tuesday at 10:30 AM. Reply C to confirm or call our front desk at (555) 234-8900 if you need to reschedule.',
  },
];

export interface SampleUrlPreset {
  id: string;
  label: string;
  url: string;
}

export const SAMPLE_URLS: SampleUrlPreset[] = [
  {
    id: 'fake_paypal',
    label: 'Lookalike PayPal Login',
    url: 'http://paypa1-security-verify.xyz/signin/update-billing',
  },
  {
    id: 'fake_amazon',
    label: 'Suspicious Amazon Alert',
    url: 'https://amazon-account-suspended.top/verify-card',
  },
  {
    id: 'official_google',
    label: 'Official Google Safety',
    url: 'https://safety.google',
  },
];

/**
 * Generates a realistic, high-DPI phone screenshot PNG of a suspicious bank SMS
 * using HTML5 Canvas so users and judges can immediately test the live Screenshot
 * Analysis workflow with crisp, readable text.
 */
export function generateSampleBankSmsScreenshot(): string {
  const canvas = document.createElement('canvas');
  canvas.width = 720;
  canvas.height = 960;
  const ctx = canvas.getContext('2d');
  if (!ctx) return '';

  // Soft outer backdrop
  ctx.fillStyle = '#F1F5F9';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Phone frame
  ctx.fillStyle = '#FFFFFF';
  ctx.strokeStyle = '#CBD5E1';
  ctx.lineWidth = 4;
  ctx.beginPath();
  ctx.roundRect(60, 40, 600, 880, 42);
  ctx.fill();
  ctx.stroke();

  // Status bar
  ctx.fillStyle = '#0F172A';
  ctx.font = '600 20px system-ui, -apple-system, sans-serif';
  ctx.fillText('9:41 AM', 100, 92);
  ctx.fillText('5G   94%', 535, 92);

  // Header bar
  ctx.fillStyle = '#F8FAFC';
  ctx.fillRect(62, 118, 596, 86);
  ctx.strokeStyle = '#E2E8F0';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(62, 204);
  ctx.lineTo(658, 204);
  ctx.stroke();

  // Sender Avatar circle
  ctx.fillStyle = '#CBD5E1';
  ctx.beginPath();
  ctx.arc(360, 146, 20, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = '#334155';
  ctx.font = '700 16px system-ui, -apple-system, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('BA', 360, 152);

  ctx.fillStyle = '#0F172A';
  ctx.font = '700 20px system-ui, -apple-system, sans-serif';
  ctx.fillText('Bank-Alert (+1 800-555-0199)', 360, 190);
  ctx.textAlign = 'left';

  // Timestamp
  ctx.fillStyle = '#64748B';
  ctx.font = '500 16px system-ui, -apple-system, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('Today 9:38 AM', 360, 245);
  ctx.textAlign = 'left';

  // Incoming SMS Bubble
  ctx.fillStyle = '#E9EEF6';
  ctx.beginPath();
  ctx.roundRect(96, 275, 495, 370, 24);
  ctx.fill();

  const lines = [
    'URGENT BANK SECURITY ALERT:',
    '',
    'Your checking account and debit card',
    'have been temporarily suspended due',
    'to suspicious login activity.',
    '',
    'Verify your identity within 2 hours at',
    'http://chase-verify-secure.xyz/auth',
    'or your funds will be permanently',
    'frozen.',
  ];

  let y = 322;
  for (const line of lines) {
    if (line.startsWith('http')) {
      ctx.fillStyle = '#1D4ED8';
      ctx.font = '600 23px system-ui, -apple-system, sans-serif';
    } else if (line.startsWith('URGENT')) {
      ctx.fillStyle = '#0F172A';
      ctx.font = '700 23px system-ui, -apple-system, sans-serif';
    } else {
      ctx.fillStyle = '#1E293B';
      ctx.font = '500 23px system-ui, -apple-system, sans-serif';
    }
    ctx.fillText(line, 124, y);
    y += 32;
  }

  // Bottom SMS compose bar
  ctx.fillStyle = '#F8FAFC';
  ctx.strokeStyle = '#CBD5E1';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.roundRect(96, 830, 528, 56, 28);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = '#94A3B8';
  ctx.font = '500 20px system-ui, -apple-system, sans-serif';
  ctx.fillText('Text Message', 124, 865);

  return canvas.toDataURL('image/png');
}

export const INITIAL_SAMPLE_HISTORY: ScanResult[] = [
  {
    id: 'sample_bank_1',
    createdAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
    channel: 'screenshot',
    inputSummary: 'URGENT BANK SECURITY ALERT: Your checking account and debit card have been temporarily suspended...',
    extractedText:
      'URGENT BANK SECURITY ALERT: Your checking account and debit card have been temporarily suspended due to suspicious login activity. Verify your identity within 2 hours at http://chase-verify-secure.xyz/auth or your funds will be permanently frozen.',
    riskLevel: 'High',
    scamCategory: 'Bank Impersonation',
    headline: 'Fake bank security alert trying to steal your login details',
    beginnerSummary:
      'This is a classic phishing text pretending to be your bank. Do not tap the link—real banks never threaten to freeze your money in 2 hours over a text link.',
    plainExplanation:
      'Scammers create panic by claiming your debit card is suspended so you rush to click their link without checking the web address. Notice the link ends in ".xyz" and uses unencrypted HTTP instead of your bank’s official ".com" website.',
    suspiciousPhrases: [
      {
        phrase: 'URGENT BANK SECURITY ALERT:',
        tactic: 'Panic Trigger',
        reason: 'Scammers open with alarming capital letters to make you act quickly without thinking.',
        severity: 'high',
      },
      {
        phrase: 'within 2 hours',
        tactic: 'Artificial Urgency',
        reason: 'Strict countdown deadlines are designed to rush you before you call your real bank.',
        severity: 'high',
      },
      {
        phrase: 'http://chase-verify-secure.xyz/auth',
        tactic: 'Lookalike Phishing Link',
        reason: 'This is not Chase’s official website. Real banks do not use ".xyz" domains or insecure HTTP links.',
        severity: 'high',
      },
      {
        phrase: 'funds will be permanently frozen',
        tactic: 'Fear & Intimidation',
        reason: 'Threatening permanent loss of money is a common manipulation tactic.',
        severity: 'high',
      },
    ],
    urlAnalysis: {
      normalizedUrl: 'http://chase-verify-secure.xyz/auth',
      hostname: 'chase-verify-secure.xyz',
      protocol: 'http',
      isHttps: false,
      dnsResolved: false,
      resolvedIpsCount: 0,
      httpStatus: null,
      finalUrl: null,
      redirected: false,
      suspiciousPatterns: [
        'Uses unencrypted HTTP instead of secure HTTPS.',
        'Uses a ".xyz" domain ending frequently abused in temporary scam campaigns.',
        'Domain contains 2 hyphens, a common pattern in fake login pages.',
        'Mentions "Chase" in an unofficial domain name.',
        'Contains high-risk account/action keywords (verify, secure, auth).',
      ],
      tldRisk: 'high',
      lookalikeBrand: 'Chase',
      isShortener: false,
      hasIpAddress: false,
      hasPunycode: false,
    },
    safetySteps: [
      'Delete the text message and block the sender number on your phone.',
      'If you want to check your account, open your bank’s official app or call the phone number printed on the back of your debit card.',
      'Forward suspicious texts to 7726 (SPAM) to help your mobile carrier block future scams.',
    ],
    doNotDo: [
      'Do not tap the link or enter your banking username, password, or PIN.',
      'Do not reply to the message or call any phone number listed inside the text.',
    ],
    urgentHelpNote:
      'If you already tapped the link and typed your password, call your bank immediately using the number on the back of your card and change your online banking password.',
    isSample: true,
  },
  {
    id: 'sample_url_2',
    createdAt: new Date(Date.now() - 1000 * 60 * 140).toISOString(),
    channel: 'url',
    inputSummary: 'http://paypa1-security-verify.xyz/signin/update-billing',
    extractedText: 'http://paypa1-security-verify.xyz/signin/update-billing',
    riskLevel: 'High',
    scamCategory: 'Lookalike Login Phishing',
    headline: 'Fake PayPal link using the number "1" instead of letter "l"',
    beginnerSummary:
      'This website pretends to be PayPal, but it spells the name with the number "1" (paypa1) and uses an unencrypted ".xyz" web address.',
    plainExplanation:
      'Fraudsters register lookalike web addresses hoping people glancing on a phone screen will not notice the swapped letter. Real PayPal login pages always use "paypal.com" with HTTPS.',
    suspiciousPhrases: [
      {
        phrase: 'paypa1-security-verify.xyz',
        tactic: 'Character Swapping (Typosquatting)',
        reason: 'Replaces the letter "l" with the number "1" and uses a ".xyz" ending instead of paypal.com.',
        severity: 'high',
      },
      {
        phrase: 'update-billing',
        tactic: 'Card Harvesting Path',
        reason: 'Designed to trick visitors into typing credit card details on a fake form.',
        severity: 'medium',
      },
    ],
    urlAnalysis: {
      normalizedUrl: 'http://paypa1-security-verify.xyz/signin/update-billing',
      hostname: 'paypa1-security-verify.xyz',
      protocol: 'http',
      isHttps: false,
      dnsResolved: false,
      resolvedIpsCount: 0,
      httpStatus: null,
      finalUrl: null,
      redirected: false,
      suspiciousPatterns: [
        'Uses unencrypted HTTP instead of secure HTTPS.',
        'Uses a ".xyz" domain ending frequently abused in temporary scam campaigns.',
        'Mentions "Paypal" in an unofficial domain name.',
        'Contains high-risk account/action keywords (signin, update, billing).',
      ],
      tldRisk: 'high',
      lookalikeBrand: 'Paypal',
      isShortener: false,
      hasIpAddress: false,
      hasPunycode: false,
    },
    safetySteps: [
      'Close the browser tab immediately without entering any details.',
      'Open PayPal directly by typing paypal.com yourself or opening the official mobile app.',
    ],
    doNotDo: [
      'Do not sign in or type your card number on this page.',
    ],
    isSample: true,
  },
  {
    id: 'sample_safe_3',
    createdAt: new Date(Date.now() - 1000 * 60 * 310).toISOString(),
    channel: 'message',
    inputSummary: 'Reminder from Oakridge Family Dental: Your cleaning appointment with Dr. Patel is scheduled...',
    extractedText:
      'Reminder from Oakridge Family Dental: Your cleaning appointment with Dr. Patel is scheduled for Tuesday at 10:30 AM. Reply C to confirm or call our front desk at (555) 234-8900 if you need to reschedule.',
    riskLevel: 'Low',
    scamCategory: 'Safe Appointment Reminder',
    headline: 'Normal appointment reminder with no suspicious links or demands',
    beginnerSummary:
      'This message looks safe. It does not ask for passwords, money, gift cards, or urgent logins on an unfamiliar website.',
    plainExplanation:
      'Legitimate appointment reminders simply share your time and offer a simple confirmation reply or a phone number to call. Even so, only confirm if you actually booked an appointment with this clinic.',
    suspiciousPhrases: [],
    safetySteps: [
      'Confirm only if you recognize the clinic and actually have an upcoming visit.',
      'If unsure, call the clinic using the phone number from your own contacts or their official website.',
    ],
    doNotDo: [
      'No urgent warnings apply, though you should never share payment info over text.',
    ],
    isSample: true,
  },
];
