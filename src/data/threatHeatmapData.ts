export type RegionId =
  | 'north-america'
  | 'europe'
  | 'south-asia'
  | 'east-asia-pacific'
  | 'latin-america'
  | 'middle-east-africa';

export type ScamTypeId =
  | 'bank-impersonation'
  | 'delivery-sms'
  | 'job-scams'
  | 'otp-tech-support'
  | 'crypto-investment'
  | 'gov-tax-alerts';

export interface RegionalHotspot {
  id: string;
  city: string;
  regionId: RegionId;
  coordinates: [number, number]; // [lon, lat]
  alertLevel: number; // 0-100
  topThreat: ScamTypeId;
}

export interface RegionalScamCell {
  regionId: RegionId;
  scamTypeId: ScamTypeId;
  intensity7d: number; // 0-100
  intensity30d: number; // 0-100
  weeklyDeltaPct: number;
  primaryChannel: 'SMS' | 'WhatsApp' | 'Email' | 'Phishing Link';
  localExample: string;
  watchOutFor: string[];
}

export interface RegionInfo {
  id: RegionId;
  name: string;
  shortName: string;
  hubs: string;
  center: [number, number];
}

export interface ScamTypeInfo {
  id: ScamTypeId;
  label: string;
  shortLabel: string;
  description: string;
}

export const REGIONS: RegionInfo[] = [
  {
    id: 'north-america',
    name: 'North America',
    shortName: 'N. America',
    hubs: 'US & Canada (USPS, Zelle, major retail banks)',
    center: [-98, 40],
  },
  {
    id: 'europe',
    name: 'Europe',
    shortName: 'Europe',
    hubs: 'UK, EU & Nordics (Royal Mail, DHL, SEPA, HMRC)',
    center: [12, 50],
  },
  {
    id: 'south-asia',
    name: 'South & Southeast Asia',
    shortName: 'S. & SE Asia',
    hubs: 'India, Singapore, Malaysia & Philippines (UPI, WhatsApp, Telegram)',
    center: [88, 17],
  },
  {
    id: 'east-asia-pacific',
    name: 'East Asia & Pacific',
    shortName: 'E. Asia & AU',
    hubs: 'Australia, Japan & South Korea (AusPost, LINE, MyGov)',
    center: [134, 15],
  },
  {
    id: 'latin-america',
    name: 'Latin America',
    shortName: 'LatAm',
    hubs: 'Brazil, Mexico & Colombia (PIX, Mercado Pago, WhatsApp)',
    center: [-60, -14],
  },
  {
    id: 'middle-east-africa',
    name: 'Middle East & Africa',
    shortName: 'MEA',
    hubs: 'UAE, Saudi Arabia, Nigeria & South Africa (Mobile Money, Emirates Post)',
    center: [26, 8],
  },
];

export const SCAM_TYPES: ScamTypeInfo[] = [
  {
    id: 'bank-impersonation',
    label: 'Bank Impersonation',
    shortLabel: 'Bank Alerts',
    description: 'Fake fraud alerts claiming your card or account is locked.',
  },
  {
    id: 'delivery-sms',
    label: 'Package Delivery SMS',
    shortLabel: 'Delivery SMS',
    description: 'Texts requesting a small fee or address update for a held parcel.',
  },
  {
    id: 'job-scams',
    label: 'Remote Job & Task Scams',
    shortLabel: 'Job Scams',
    description: 'High-pay part-time offers demanding upfront deposits or gift cards.',
  },
  {
    id: 'otp-tech-support',
    label: 'OTP & Tech Support',
    shortLabel: 'OTP / Support',
    description: 'Tricks to steal 6-digit login codes or install remote screen-sharing apps.',
  },
  {
    id: 'crypto-investment',
    label: 'Crypto & Pig Butchering',
    shortLabel: 'Investment',
    description: 'Fake trading platforms promising guaranteed daily returns.',
  },
  {
    id: 'gov-tax-alerts',
    label: 'Gov, Toll & Tax Alerts',
    shortLabel: 'Gov / Tolls',
    description: 'Urgent unpaid road toll, tax refund, or ID renewal threats.',
  },
];

export const REGIONAL_CELLS: RegionalScamCell[] = [
  // North America
  {
    regionId: 'north-america',
    scamTypeId: 'bank-impersonation',
    intensity7d: 88,
    intensity30d: 82,
    weeklyDeltaPct: 19,
    primaryChannel: 'SMS',
    localExample: 'CHASE/ZELLE Alert: Did you authorize $1,450? Reply NO or verify at http://chase-alert-verify.xyz',
    watchOutFor: ['Spoofed bank alert texts asking to verify Zelle transfers', 'Links ending in .xyz or .top instead of .com'],
  },
  {
    regionId: 'north-america',
    scamTypeId: 'delivery-sms',
    intensity7d: 92,
    intensity30d: 86,
    weeklyDeltaPct: 28,
    primaryChannel: 'SMS',
    localExample: 'USPS: Your parcel cannot be delivered due to missing house number. Confirm at usps-redelivery-help.top',
    watchOutFor: ['Fake USPS, UPS, or FedEx redelivery fee links', 'Requests for credit card details for a $0.30–$3 fee'],
  },
  {
    regionId: 'north-america',
    scamTypeId: 'job-scams',
    intensity7d: 71,
    intensity30d: 68,
    weeklyDeltaPct: 14,
    primaryChannel: 'WhatsApp',
    localExample: 'Hi from Apex Recruiting! Earn $350/day rating apps from home. Message our mentor on WhatsApp/Telegram.',
    watchOutFor: ['Unsolicited recruiter texts moving to WhatsApp or Telegram', 'Asking for a refundable training deposit'],
  },
  {
    regionId: 'north-america',
    scamTypeId: 'otp-tech-support',
    intensity7d: 64,
    intensity30d: 61,
    weeklyDeltaPct: 8,
    primaryChannel: 'Email',
    localExample: 'GeekSquad Auto-Renewal: $499 charged today. Call +1-888-555-0142 immediately to cancel.',
    watchOutFor: ['Fake antivirus/GeekSquad invoice emails with a phone number', 'Requests to install AnyDesk or TeamViewer'],
  },
  {
    regionId: 'north-america',
    scamTypeId: 'crypto-investment',
    intensity7d: 58,
    intensity30d: 60,
    weeklyDeltaPct: 5,
    primaryChannel: 'WhatsApp',
    localExample: 'Wrong-number friendly text that turns into daily crypto trading tips on an unfamiliar exchange.',
    watchOutFor: ['Strangers starting casual chats and introducing crypto platforms', 'Withdrawals blocked until you pay "taxes"'],
  },
  {
    regionId: 'north-america',
    scamTypeId: 'gov-tax-alerts',
    intensity7d: 84,
    intensity30d: 76,
    weeklyDeltaPct: 31,
    primaryChannel: 'SMS',
    localExample: 'SunPass / E-ZPass Final Notice: Pay $6.99 unpaid toll by midnight to avoid license suspension.',
    watchOutFor: ['Unpaid highway toll smishing (E-ZPass, SunPass, FasTrak)', 'Urgent midnight deadline threats'],
  },

  // Europe
  {
    regionId: 'europe',
    scamTypeId: 'bank-impersonation',
    intensity7d: 81,
    intensity30d: 79,
    weeklyDeltaPct: 15,
    primaryChannel: 'SMS',
    localExample: 'Your IBAN / Revolut security check failed. Confirm your device now to avoid SEPA transfer lock.',
    watchOutFor: ['Fake Revolut, Monzo, Barclays, or Deutsche Bank login links', 'Calls claiming you must move funds to a "safe account"'],
  },
  {
    regionId: 'europe',
    scamTypeId: 'delivery-sms',
    intensity7d: 86,
    intensity30d: 84,
    weeklyDeltaPct: 21,
    primaryChannel: 'SMS',
    localExample: 'Royal Mail / DHL: Customs duty £1.99 unpaid. Pay online today before your parcel is returned.',
    watchOutFor: ['Fake Royal Mail, DPD, or DHL customs fee links', 'Lookalike domains using hyphens or country typos'],
  },
  {
    regionId: 'europe',
    scamTypeId: 'job-scams',
    intensity7d: 59,
    intensity30d: 55,
    weeklyDeltaPct: 11,
    primaryChannel: 'WhatsApp',
    localExample: 'Booking.com / Amazon product optimization role: €250/day flexible hours, reply YES on WhatsApp.',
    watchOutFor: ['"Task boosting" scams using well-known travel or retail brands', 'Small initial payouts followed by large deposit traps'],
  },
  {
    regionId: 'europe',
    scamTypeId: 'otp-tech-support',
    intensity7d: 62,
    intensity30d: 58,
    weeklyDeltaPct: 9,
    primaryChannel: 'WhatsApp',
    localExample: 'Hi Mum/Dad, I dropped my phone and this is my temporary number. Can you send €650 for an urgent bill?',
    watchOutFor: ['"Hi Mum/Dad" family emergency impersonation on WhatsApp', 'Requests to transfer money to an unfamiliar bank name'],
  },
  {
    regionId: 'europe',
    scamTypeId: 'crypto-investment',
    intensity7d: 54,
    intensity30d: 57,
    weeklyDeltaPct: 4,
    primaryChannel: 'Phishing Link',
    localExample: 'Celebrity-endorsed AI trading platform guaranteeing €1,200 weekly passive profit.',
    watchOutFor: ['Fake news articles with deepfake endorsements', 'High-pressure phone calls after signing up'],
  },
  {
    regionId: 'europe',
    scamTypeId: 'gov-tax-alerts',
    intensity7d: 74,
    intensity30d: 71,
    weeklyDeltaPct: 17,
    primaryChannel: 'Email',
    localExample: 'HMRC / Tax Office: You are eligible for a €420 tax rebate. Claim within 48 hours.',
    watchOutFor: ['Tax rebate emails asking for debit card numbers', 'Non-governmental web addresses (not .gov.uk or official portal)'],
  },

  // South & Southeast Asia
  {
    regionId: 'south-asia',
    scamTypeId: 'bank-impersonation',
    intensity7d: 85,
    intensity30d: 83,
    weeklyDeltaPct: 16,
    primaryChannel: 'SMS',
    localExample: 'Dear Customer, your KYC / PAN update is pending. Account will freeze today—click link to verify.',
    watchOutFor: ['Fake KYC / PAN expiry warnings threatening bank freeze', 'Links asking for netbanking PIN or UPI PIN'],
  },
  {
    regionId: 'south-asia',
    scamTypeId: 'delivery-sms',
    intensity7d: 67,
    intensity30d: 64,
    weeklyDeltaPct: 12,
    primaryChannel: 'SMS',
    localExample: 'India Post / SingPost: Parcel held at warehouse due to incomplete address. Update details immediately.',
    watchOutFor: ['Unfamiliar APK download links sent as "tracking apps"', 'Small fee links harvesting card OTPs'],
  },
  {
    regionId: 'south-asia',
    scamTypeId: 'job-scams',
    intensity7d: 95,
    intensity30d: 91,
    weeklyDeltaPct: 34,
    primaryChannel: 'WhatsApp',
    localExample: 'Like YouTube videos or review hotels for ₹3,000–₹8,000/day! Join our Telegram task group now.',
    watchOutFor: ['Paid "like & subscribe" or hotel-review Telegram tasks', 'Asking you to prepaid-invest into VIP task levels'],
  },
  {
    regionId: 'south-asia',
    scamTypeId: 'otp-tech-support',
    intensity7d: 90,
    intensity30d: 87,
    weeklyDeltaPct: 24,
    primaryChannel: 'WhatsApp',
    localExample: 'To receive your refund or OLX buyer payment, scan this QR code or enter your UPI PIN.',
    watchOutFor: ['QR codes sent to "receive" money (UPI PIN is only for sending!)', 'Fake "digital arrest" video calls claiming to be cyber police'],
  },
  {
    regionId: 'south-asia',
    scamTypeId: 'crypto-investment',
    intensity7d: 79,
    intensity30d: 75,
    weeklyDeltaPct: 22,
    primaryChannel: 'WhatsApp',
    localExample: 'Join our VIP Stock & Crypto Institutional Group for 300% guaranteed IPO allotment profits.',
    watchOutFor: ['Fake WhatsApp stock-tip groups impersonating registered brokers', 'Side-loaded trading apps not on official app stores'],
  },
  {
    regionId: 'south-asia',
    scamTypeId: 'gov-tax-alerts',
    intensity7d: 72,
    intensity30d: 69,
    weeklyDeltaPct: 18,
    primaryChannel: 'SMS',
    localExample: 'Electricity Board Notice: Your power will be disconnected tonight at 9:30 PM because last bill was not updated.',
    watchOutFor: ['Fake electricity/utility disconnection threats', 'Asking you to call a personal mobile number or install support apps'],
  },

  // East Asia & Pacific
  {
    regionId: 'east-asia-pacific',
    scamTypeId: 'bank-impersonation',
    intensity7d: 76,
    intensity30d: 73,
    weeklyDeltaPct: 13,
    primaryChannel: 'SMS',
    localExample: 'CommBank / NAB / MUFG Security: New PayID device linked. Cancel immediately if this was not you.',
    watchOutFor: ['Fake banking texts using your real bank name inside the same SMS thread', 'Requests to read back SMS security codes'],
  },
  {
    regionId: 'east-asia-pacific',
    scamTypeId: 'delivery-sms',
    intensity7d: 83,
    intensity30d: 80,
    weeklyDeltaPct: 20,
    primaryChannel: 'SMS',
    localExample: 'AusPost / Yamato: Delivery attempt failed. Reschedule within 24h at auspost-track-info.click',
    watchOutFor: ['Fake AusPost, NZ Post, or courier links', 'Domains ending in .click or .info'],
  },
  {
    regionId: 'east-asia-pacific',
    scamTypeId: 'job-scams',
    intensity7d: 63,
    intensity30d: 59,
    weeklyDeltaPct: 10,
    primaryChannel: 'WhatsApp',
    localExample: 'Flexible online e-commerce order assistant needed, $300/day, message via LINE or WhatsApp.',
    watchOutFor: ['High daily wages for simple tapping tasks', 'Payments requested in cryptocurrency or gift cards'],
  },
  {
    regionId: 'east-asia-pacific',
    scamTypeId: 'otp-tech-support',
    intensity7d: 68,
    intensity30d: 66,
    weeklyDeltaPct: 11,
    primaryChannel: 'Phishing Link',
    localExample: 'Apple ID / LINE account sign-in blocked from overseas IP. Verify credentials to keep your contacts.',
    watchOutFor: ['Phishing login pages mimicking Apple, LINE, or KakaoTalk', 'Pressure to disable two-factor alerts'],
  },
  {
    regionId: 'east-asia-pacific',
    scamTypeId: 'crypto-investment',
    intensity7d: 74,
    intensity30d: 72,
    weeklyDeltaPct: 15,
    primaryChannel: 'WhatsApp',
    localExample: 'Exclusive AI wealth seminar group with guaranteed weekly FX & crypto signals.',
    watchOutFor: ['Social media ads impersonating finance commentators', 'Requests to deposit funds into unfamiliar wallet addresses'],
  },
  {
    regionId: 'east-asia-pacific',
    scamTypeId: 'gov-tax-alerts',
    intensity7d: 79,
    intensity30d: 77,
    weeklyDeltaPct: 23,
    primaryChannel: 'SMS',
    localExample: 'myGov / Linkt Toll Notice: Your tax return or toll account requires immediate bank card confirmation.',
    watchOutFor: ['Fake myGov or Linkt road toll texts', 'Links that do not end in official .gov.au domains'],
  },

  // Latin America
  {
    regionId: 'latin-america',
    scamTypeId: 'bank-impersonation',
    intensity7d: 89,
    intensity30d: 86,
    weeklyDeltaPct: 22,
    primaryChannel: 'WhatsApp',
    localExample: 'Banco / PIX Security: A transfer of R$2,800 is pending. Confirm your app password to block it.',
    watchOutFor: ['Fake bank support messages on WhatsApp', 'Requests to generate a "test" PIX transfer to cancel fraud'],
  },
  {
    regionId: 'latin-america',
    scamTypeId: 'delivery-sms',
    intensity7d: 77,
    intensity30d: 74,
    weeklyDeltaPct: 16,
    primaryChannel: 'SMS',
    localExample: 'Correios / Estafeta: Your international package is held at customs. Pay release tax online.',
    watchOutFor: ['Fake postal customs tax pages', 'Urgent countdown timers on mobile web pages'],
  },
  {
    regionId: 'latin-america',
    scamTypeId: 'job-scams',
    intensity7d: 72,
    intensity30d: 69,
    weeklyDeltaPct: 14,
    primaryChannel: 'WhatsApp',
    localExample: 'Work from home evaluating Mercado Libre products! Guaranteed daily pay via WhatsApp.',
    watchOutFor: ['Fake e-commerce review jobs asking for upfront registration', 'Unverified Telegram payment groups'],
  },
  {
    regionId: 'latin-america',
    scamTypeId: 'otp-tech-support',
    intensity7d: 84,
    intensity30d: 81,
    weeklyDeltaPct: 19,
    primaryChannel: 'WhatsApp',
    localExample: 'Marketplace buyer: I just sent a WhatsApp verification code to confirm you are a real seller—read it back.',
    watchOutFor: ['WhatsApp account takeover scams asking for your 6-digit SMS code', 'Cloning accounts to message friends for urgent loans'],
  },
  {
    regionId: 'latin-america',
    scamTypeId: 'crypto-investment',
    intensity7d: 61,
    intensity30d: 58,
    weeklyDeltaPct: 9,
    primaryChannel: 'Phishing Link',
    localExample: 'Double your instant transfer in 2 hours using our automated crypto arbitrage bot.',
    watchOutFor: ['Guaranteed "double your money" promises', 'Fake live screenshots of payouts'],
  },
  {
    regionId: 'latin-america',
    scamTypeId: 'gov-tax-alerts',
    intensity7d: 65,
    intensity30d: 63,
    weeklyDeltaPct: 10,
    primaryChannel: 'SMS',
    localExample: 'Government benefit / bonus voucher waiting: enter your national ID and bank card to claim.',
    watchOutFor: ['Fake government cash-grant links shared on messaging apps', 'Asking for bank card CVV to "receive" a grant'],
  },

  // Middle East & Africa
  {
    regionId: 'middle-east-africa',
    scamTypeId: 'bank-impersonation',
    intensity7d: 86,
    intensity30d: 82,
    weeklyDeltaPct: 20,
    primaryChannel: 'SMS',
    localExample: 'Central Bank / Mobile Money Alert: Your BVN or Emirates ID verification expired. Update within 3 hours.',
    watchOutFor: ['Fake ID / BVN update threats', 'Requests for mobile wallet PIN or card CVV'],
  },
  {
    regionId: 'middle-east-africa',
    scamTypeId: 'delivery-sms',
    intensity7d: 74,
    intensity30d: 71,
    weeklyDeltaPct: 15,
    primaryChannel: 'SMS',
    localExample: 'Emirates Post / Aramex: Parcel awaiting small clearance fee. Click link to schedule delivery.',
    watchOutFor: ['Fake courier clearance fees', 'Lookalike domains mimicking Aramex, DHL, or national post'],
  },
  {
    regionId: 'middle-east-africa',
    scamTypeId: 'job-scams',
    intensity7d: 82,
    intensity30d: 78,
    weeklyDeltaPct: 25,
    primaryChannel: 'WhatsApp',
    localExample: 'Urgent overseas hospitality & logistics hiring! Pay visa processing fee today to secure your offer.',
    watchOutFor: ['Fake overseas work-visa offers asking for processing fees', 'Unofficial Gmail/WhatsApp recruiter contacts'],
  },
  {
    regionId: 'middle-east-africa',
    scamTypeId: 'otp-tech-support',
    intensity7d: 79,
    intensity30d: 77,
    weeklyDeltaPct: 17,
    primaryChannel: 'SMS',
    localExample: 'You accidentally received a mobile money transfer—please share the reversal OTP code we just sent.',
    watchOutFor: ['Fake "mistaken transfer" reversal OTP tricks', 'Callers pretending to be telecom support resetting your SIM'],
  },
  {
    regionId: 'middle-east-africa',
    scamTypeId: 'crypto-investment',
    intensity7d: 68,
    intensity30d: 65,
    weeklyDeltaPct: 13,
    primaryChannel: 'WhatsApp',
    localExample: 'VIP Forex & Gold investment signal group—start with $100 and withdraw $950 in 48 hours.',
    watchOutFor: ['Unrealistic 48-hour profit guarantees', 'Pressure to recruit friends or pay withdrawal unlock fees'],
  },
  {
    regionId: 'middle-east-africa',
    scamTypeId: 'gov-tax-alerts',
    intensity7d: 71,
    intensity30d: 68,
    weeklyDeltaPct: 14,
    primaryChannel: 'SMS',
    localExample: 'Traffic Fine / Salik Notice: Unpaid violation detected. Settle immediately to avoid late penalties.',
    watchOutFor: ['Fake traffic fine or toll payment links', 'Non-official links asking for immediate debit card input'],
  },
];

export const REGIONAL_HOTSPOTS: RegionalHotspot[] = [
  { id: 'nyc', city: 'New York', regionId: 'north-america', coordinates: [-74.0, 40.7], alertLevel: 91, topThreat: 'delivery-sms' },
  { id: 'tor', city: 'Toronto', regionId: 'north-america', coordinates: [-79.4, 43.7], alertLevel: 82, topThreat: 'bank-impersonation' },
  { id: 'sf', city: 'San Francisco', regionId: 'north-america', coordinates: [-122.4, 37.8], alertLevel: 85, topThreat: 'gov-tax-alerts' },
  { id: 'lon', city: 'London', regionId: 'europe', coordinates: [-0.1, 51.5], alertLevel: 86, topThreat: 'delivery-sms' },
  { id: 'ber', city: 'Berlin', regionId: 'europe', coordinates: [13.4, 52.5], alertLevel: 78, topThreat: 'bank-impersonation' },
  { id: 'par', city: 'Paris', regionId: 'europe', coordinates: [2.35, 48.85], alertLevel: 80, topThreat: 'gov-tax-alerts' },
  { id: 'bom', city: 'Mumbai', regionId: 'south-asia', coordinates: [72.87, 19.07], alertLevel: 94, topThreat: 'job-scams' },
  { id: 'blr', city: 'Bengaluru', regionId: 'south-asia', coordinates: [77.59, 12.97], alertLevel: 92, topThreat: 'otp-tech-support' },
  { id: 'sin', city: 'Singapore', regionId: 'south-asia', coordinates: [103.82, 1.35], alertLevel: 88, topThreat: 'job-scams' },
  { id: 'tok', city: 'Tokyo', regionId: 'east-asia-pacific', coordinates: [139.69, 35.68], alertLevel: 79, topThreat: 'delivery-sms' },
  { id: 'syd', city: 'Sydney', regionId: 'east-asia-pacific', coordinates: [151.2, -33.86], alertLevel: 84, topThreat: 'gov-tax-alerts' },
  { id: 'sao', city: 'São Paulo', regionId: 'latin-america', coordinates: [-46.63, -23.55], alertLevel: 89, topThreat: 'bank-impersonation' },
  { id: 'mex', city: 'Mexico City', regionId: 'latin-america', coordinates: [-99.13, 19.43], alertLevel: 83, topThreat: 'otp-tech-support' },
  { id: 'dxb', city: 'Dubai', regionId: 'middle-east-africa', coordinates: [55.27, 25.2], alertLevel: 84, topThreat: 'delivery-sms' },
  { id: 'los', city: 'Lagos', regionId: 'middle-east-africa', coordinates: [3.38, 6.52], alertLevel: 86, topThreat: 'bank-impersonation' },
  { id: 'jnb', city: 'Johannesburg', regionId: 'middle-east-africa', coordinates: [28.04, -26.2], alertLevel: 80, topThreat: 'job-scams' },
];

export function detectUserRegionFromTimezone(): RegionId {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    if (tz.startsWith('America/')) {
      if (
        tz.includes('Sao_Paulo') ||
        tz.includes('Buenos_Aires') ||
        tz.includes('Bogota') ||
        tz.includes('Lima') ||
        tz.includes('Santiago') ||
        tz.includes('Mexico_City') ||
        tz.includes('Caracas')
      ) {
        return 'latin-america';
      }
      return 'north-america';
    }
    if (tz.startsWith('Europe/')) {
      return 'europe';
    }
    if (
      tz.startsWith('Asia/Kolkata') ||
      tz.startsWith('Asia/Calcutta') ||
      tz.startsWith('Asia/Dhaka') ||
      tz.startsWith('Asia/Karachi') ||
      tz.startsWith('Asia/Colombo') ||
      tz.startsWith('Asia/Singapore') ||
      tz.startsWith('Asia/Bangkok') ||
      tz.startsWith('Asia/Jakarta') ||
      tz.startsWith('Asia/Manila') ||
      tz.startsWith('Asia/Kuala_Lumpur')
    ) {
      return 'south-asia';
    }
    if (tz.startsWith('Australia/') || tz.startsWith('Pacific/') || tz.startsWith('Asia/Tokyo') || tz.startsWith('Asia/Seoul')) {
      return 'east-asia-pacific';
    }
    if (tz.startsWith('Africa/') || tz.startsWith('Asia/Dubai') || tz.startsWith('Asia/Riyadh')) {
      return 'middle-east-africa';
    }
  } catch {
    // Fallback below
  }
  return 'north-america';
}

// Lightweight self-contained GeoJSON of simplified global regions for offline-safe D3 geoNaturalEarth1 rendering
export interface WorldRegionFeature {
  type: 'Feature';
  properties: { regionId: RegionId; name: string };
  geometry: {
    type: 'Polygon';
    coordinates: number[][][];
  };
}

export const WORLD_REGIONS_GEOJSON: {
  type: 'FeatureCollection';
  features: WorldRegionFeature[];
} = {
  type: 'FeatureCollection',
  features: [
    {
      type: 'Feature',
      properties: { regionId: 'north-america', name: 'North America' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-168, 66], [-140, 70], [-95, 72], [-60, 62], [-53, 47], [-70, 42],
            [-80, 26], [-87, 21], [-97, 20], [-105, 19], [-115, 31], [-124, 40],
            [-128, 52], [-152, 58], [-168, 66],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      properties: { regionId: 'latin-america', name: 'Latin America' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-104, 19], [-88, 21], [-78, 9], [-62, 11], [-50, 1], [-35, -6],
            [-40, -21], [-53, -33], [-66, -54], [-75, -52], [-73, -37], [-71, -18],
            [-81, -5], [-79, 8], [-92, 14], [-104, 19],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      properties: { regionId: 'europe', name: 'Europe' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-10, 36], [-9, 43], [-4, 48], [-8, 55], [2, 58], [10, 64],
            [26, 70], [42, 67], [44, 52], [36, 44], [27, 41], [18, 40],
            [12, 43], [6, 43], [-2, 37], [-10, 36],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      properties: { regionId: 'middle-east-africa', name: 'Middle East & Africa' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-17, 15], [-13, 28], [-5, 35], [10, 37], [32, 32], [44, 37],
            [59, 25], [52, 13], [43, 11], [49, 4], [40, -10], [34, -26],
            [20, -35], [14, -22], [11, -5], [2, 5], [-10, 6], [-17, 15],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      properties: { regionId: 'south-asia', name: 'South & Southeast Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [62, 25], [70, 35], [82, 31], [94, 28], [104, 22], [109, 14],
            [104, 1], [98, 7], [91, 21], [83, 17], [78, 8], [72, 19], [66, 24], [62, 25],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      properties: { regionId: 'east-asia-pacific', name: 'East Asia & Pacific' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [105, 22], [106, 40], [124, 45], [142, 45], [144, 34], [129, 34],
            [122, 23], [116, 21], [105, 22],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      properties: { regionId: 'east-asia-pacific', name: 'Australia & Oceania' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [114, -22], [129, -12], [143, -11], [153, -25], [150, -37],
            [138, -36], [122, -34], [114, -28], [114, -22],
          ],
        ],
      },
    },
  ],
};
