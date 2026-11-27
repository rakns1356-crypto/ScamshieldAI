import { CheckCircle2, LifeBuoy, ShieldAlert } from 'lucide-react';

interface SafetyGuideProps {
  onOpenScanner: () => void;
  onOpenChat: () => void;
}

export function SafetyGuide({ onOpenScanner, onOpenChat }: SafetyGuideProps) {
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Beginner&apos;s Guide to Staying Safe Online
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Simple, memorable rules anyone can use to spot fraud before clicking or paying.
          </p>
        </div>
        <button
          type="button"
          onClick={onOpenScanner}
          className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 transition-colors min-h-[40px] whitespace-nowrap shrink-0 self-start sm:self-auto cursor-pointer"
        >
          Go to Scanner
        </button>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-200 bg-white p-6 space-y-4">
          <h2 className="text-base font-bold text-slate-900">5 Golden Rules Before You Click</h2>
          <ol className="space-y-3 text-sm text-slate-700">
            <li className="flex items-start gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-slate-100 text-xs font-bold text-slate-900">
                1
              </span>
              <span>
                <strong className="text-slate-900">Pause on urgent deadlines.</strong> Scammers say &ldquo;within 2 hours&rdquo; or &ldquo;account frozen&rdquo; so you panic instead of checking.
              </span>
            </li>
            <li className="flex items-start gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-slate-100 text-xs font-bold text-slate-900">
                2
              </span>
              <span>
                <strong className="text-slate-900">Never tap links inside unexpected texts.</strong> Open your bank, delivery, or shopping app directly on your phone instead.
              </span>
            </li>
            <li className="flex items-start gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-slate-100 text-xs font-bold text-slate-900">
                3
              </span>
              <span>
                <strong className="text-slate-900">Look closely at the web address.</strong> Fake links swap letters for numbers (like <span className="font-mono text-xs">paypa1.com</span>) or end in <span className="font-mono text-xs">.xyz</span> or <span className="font-mono text-xs">.top</span>.
              </span>
            </li>
            <li className="flex items-start gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-slate-100 text-xs font-bold text-slate-900">
                4
              </span>
              <span>
                <strong className="text-slate-900">Gift cards and crypto equal scams.</strong> No real employer, government agency, or bank ever asks to be paid with gift cards.
              </span>
            </li>
            <li className="flex items-start gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-slate-100 text-xs font-bold text-slate-900">
                5
              </span>
              <span>
                <strong className="text-slate-900">Guard one-time passcodes (OTPs).</strong> Never read a 6-digit login code out loud or forward it to anyone who texted or called you.
              </span>
            </li>
          </ol>
        </div>

        <div className="space-y-6">
          <div className="rounded-2xl border border-slate-200 bg-white p-6 space-y-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-red-600" />
              <h2 className="text-base font-bold text-slate-900">What Real Banks &amp; Agencies Never Do</h2>
            </div>
            <ul className="space-y-2.5 text-sm text-slate-700">
              <li className="flex items-start gap-2.5">
                <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5 shrink-0" />
                <span>They never ask for your full PIN, password, or 6-digit text code.</span>
              </li>
              <li className="flex items-start gap-2.5">
                <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5 shrink-0" />
                <span>They never demand immediate payment over WhatsApp, Telegram, or gift cards.</span>
              </li>
              <li className="flex items-start gap-2.5">
                <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5 shrink-0" />
                <span>They never mind if you hang up and call the official number printed on the back of your card.</span>
              </li>
            </ul>
          </div>

          <div className="rounded-2xl border border-blue-200 bg-blue-50/70 p-6 space-y-4">
            <div className="flex items-start gap-3">
              <LifeBuoy className="h-5 w-5 text-blue-700 mt-0.5 shrink-0" />
              <div className="space-y-1">
                <h2 className="text-base font-bold text-slate-900">Already Clicked or Shared Info?</h2>
                <p className="text-sm text-slate-700 leading-relaxed">
                  Take a breath—acting within the first hour makes a big difference. Freeze your card via your bank&apos;s official app, change your password, and talk with our Safety Assistant for exact recovery steps.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={onOpenChat}
              className="rounded-xl bg-blue-700 px-5 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 transition-colors min-h-[42px] cursor-pointer"
            >
              Get Step-by-Step Recovery Help
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
