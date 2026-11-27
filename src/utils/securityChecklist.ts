import type { ScanResult } from '../types/scam';

export interface ChecklistTask {
  id: string;
  title: string;
  detail: string;
  priority: 'Immediate' | 'Recommended';
}

export function buildContextualChecklist(result: ScanResult): ChecklistTask[] {
  const haystack = [
    result.scamCategory,
    result.headline,
    result.plainExplanation,
    result.extractedText,
    result.urlAnalysis?.hostname || '',
    result.urlAnalysis?.lookalikeBrand || '',
  ]
    .join(' ')
    .toLowerCase();

  const tasks: ChecklistTask[] = [];
  const addUnique = (task: ChecklistTask) => {
    if (!tasks.some((t) => t.id === task.id)) {
      tasks.push(task);
    }
  };

  if (result.riskLevel === 'Low') {
    addUnique({
      id: 'confirm-known-sender',
      title: 'Confirm you recognize the sender',
      detail: 'Make sure you expected this message or recognize the business name before replying.',
      priority: 'Recommended',
    });
    addUnique({
      id: 'enable-2fa-preventive',
      title: 'Keep Two-Factor Authentication (2FA) enabled',
      detail: 'Protect your email and financial logins with an authenticator app or passkey.',
      priority: 'Recommended',
    });
    addUnique({
      id: 'bookmark-official-sites',
      title: 'Use saved bookmarks for logins',
      detail: 'Even when a message looks safe, typing the official address yourself avoids fake links.',
      priority: 'Recommended',
    });
    return tasks;
  }

  const isBankOrPayment =
    /\b(bank|chase|wells|citibank|paypal|venmo|zelle|revolut|debit|credit|card|checking|upi|pix|billing|account)\b/.test(
      haystack
    );
  const isCredentialOrUrl =
    result.channel === 'url' ||
    Boolean(result.urlAnalysis) ||
    /\b(login|signin|password|verify|phishing|credential|lookalike)\b/.test(haystack);
  const isJobOrGiftCard =
    /\b(job|career|recruit|hr|gift card|apple card|steam|telegram|fee|task|deposit|crypto|investment)\b/.test(
      haystack
    );
  const isOtpOrSupport =
    /\b(otp|code|6-digit|pin|tech support|geek|anydesk|teamviewer|whatsapp|qr code|virus)\b/.test(
      haystack
    );
  const isDeliveryOrGov =
    /\b(usps|ups|fedex|dhl|royal mail|auspost|parcel|package|delivery|toll|e-zpass|sunpass|hmrc|irs|tax|mygov)\b/.test(
      haystack
    );

  if (isBankOrPayment) {
    addUnique({
      id: 'call-official-bank',
      title: 'Verify via the phone number on your card',
      detail: 'Ignore any phone number or link inside the suspicious message. Call the official number printed on the back of your card.',
      priority: 'Immediate',
    });
    addUnique({
      id: 'freeze-or-monitor-card',
      title: 'Check recent bank activity or freeze your card',
      detail: 'Open your official banking app to inspect recent transactions and lock your card if you entered card details.',
      priority: 'Immediate',
    });
  }

  if (isCredentialOrUrl || isBankOrPayment) {
    addUnique({
      id: 'update-password',
      title: 'Update Password on the affected service',
      detail: 'If you clicked the link or typed any login details, change your password right away—and update any other site where you used the same password.',
      priority: 'Immediate',
    });
    addUnique({
      id: 'enable-2fa',
      title: 'Enable Two-Factor Authentication (2FA)',
      detail: 'Turn on 2FA (ideally via an authenticator app or hardware passkey) so a stolen password alone cannot access your account.',
      priority: 'Immediate',
    });
  }

  if (isJobOrGiftCard) {
    addUnique({
      id: 'halt-payments-giftcards',
      title: 'Stop all fee, crypto, or gift card payments',
      detail: 'Legitimate employers never ask you to pay a starter fee or send gift cards. If you already bought a gift card, contact the card issuer immediately with your receipt.',
      priority: 'Immediate',
    });
    addUnique({
      id: 'protect-shared-identity',
      title: 'Check what personal info you shared',
      detail: 'If you sent a photo ID, bank routing number, or tax ID, place a fraud alert with your bank and credit bureau.',
      priority: 'Recommended',
    });
  }

  if (isOtpOrSupport) {
    addUnique({
      id: 'secure-2fa-pin',
      title: 'Enable Two-Step Verification PIN on messaging apps',
      detail: 'Set a 6-digit registration PIN in WhatsApp, Telegram, or email settings so attackers cannot hijack your account with an intercepted SMS code.',
      priority: 'Immediate',
    });
    addUnique({
      id: 'remove-remote-apps',
      title: 'Uninstall any requested screen-sharing apps',
      detail: 'If anyone asked you to install AnyDesk, TeamViewer, or QuickSupport, delete the app and disconnect from Wi-Fi briefly while running a security scan.',
      priority: 'Immediate',
    });
  }

  if (isDeliveryOrGov) {
    addUnique({
      id: 'check-official-portal',
      title: 'Check tracking or tolls on the official website',
      detail: 'Visit USPS, DHL, Royal Mail, or your toll agency by typing their official web address directly into a new tab.',
      priority: 'Recommended',
    });
  }

  if (result.urlAnalysis) {
    addUnique({
      id: 'clear-browser-tab',
      title: 'Close the suspicious tab & clear autofill',
      detail: 'If you opened the link earlier, close the browser tab and avoid letting your browser auto-fill saved cards or passwords.',
      priority: 'Recommended',
    });
  }

  addUnique({
    id: 'block-and-report',
    title: 'Block the sender & report the message',
    detail: 'Block the phone number or email address on your device, and forward scam texts to 7726 (SPAM) if supported by your carrier.',
    priority: 'Recommended',
  });

  return tasks.slice(0, 6);
}
