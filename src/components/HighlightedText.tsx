import { useMemo, useState } from 'react';
import { AlertCircle } from 'lucide-react';
import type { SuspiciousPhrase } from '../types/scam';

interface HighlightedTextProps {
  text: string;
  phrases: SuspiciousPhrase[];
}

interface TextSegment {
  text: string;
  match?: SuspiciousPhrase;
  index: number;
}

export function HighlightedText({ text, phrases }: HighlightedTextProps) {
  const [selectedPhrase, setSelectedPhrase] = useState<SuspiciousPhrase | null>(
    phrases.length > 0 ? phrases[0] : null
  );

  const segments = useMemo<TextSegment[]>(() => {
    if (!text) return [];
    if (!phrases || phrases.length === 0) {
      return [{ text, index: 0 }];
    }

    const lowerText = text.toLowerCase();
    const ranges: Array<{ start: number; end: number; phrase: SuspiciousPhrase }> = [];

    // Sort longest phrases first so specific phrases take precedence
    const sorted = [...phrases].sort((a, b) => b.phrase.length - a.phrase.length);

    for (const item of sorted) {
      const target = item.phrase.trim();
      if (!target) continue;

      let searchFrom = 0;
      const lowerTarget = target.toLowerCase();
      while (searchFrom < lowerText.length) {
        const idx = lowerText.indexOf(lowerTarget, searchFrom);
        if (idx === -1) break;
        const end = idx + target.length;
        const overlaps = ranges.some((r) => idx < r.end && end > r.start);
        if (!overlaps) {
          ranges.push({ start: idx, end, phrase: item });
        }
        searchFrom = end;
      }
    }

    ranges.sort((a, b) => a.start - b.start);

    const result: TextSegment[] = [];
    let cursor = 0;
    let segIdx = 0;

    for (const r of ranges) {
      if (r.start > cursor) {
        result.push({ text: text.slice(cursor, r.start), index: segIdx++ });
      }
      result.push({
        text: text.slice(r.start, r.end),
        match: r.phrase,
        index: segIdx++,
      });
      cursor = r.end;
    }

    if (cursor < text.length) {
      result.push({ text: text.slice(cursor), index: segIdx++ });
    }

    return result;
  }, [text, phrases]);

  const severityClasses = (severity: SuspiciousPhrase['severity'], isSelected: boolean) => {
    if (severity === 'high') {
      return isSelected
        ? 'bg-red-200 text-red-950 ring-2 ring-red-600'
        : 'bg-red-100 text-red-900 hover:bg-red-200 border-b-2 border-red-500';
    }
    if (severity === 'medium') {
      return isSelected
        ? 'bg-amber-200 text-amber-950 ring-2 ring-amber-600'
        : 'bg-amber-100 text-amber-900 hover:bg-amber-200 border-b-2 border-amber-500';
    }
    return isSelected
      ? 'bg-blue-200 text-blue-950 ring-2 ring-blue-600'
      : 'bg-blue-100 text-blue-900 hover:bg-blue-200 border-b-2 border-blue-500';
  };

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-[15px] leading-relaxed text-slate-800 break-words whitespace-pre-wrap">
        {segments.map((seg) =>
          seg.match ? (
            <button
              key={seg.index}
              type="button"
              onClick={() => setSelectedPhrase(seg.match!)}
              className={`inline rounded px-1 py-0.5 text-left font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 cursor-pointer ${severityClasses(
                seg.match.severity,
                selectedPhrase?.phrase === seg.match.phrase
              )}`}
            >
              {seg.text}
            </button>
          ) : (
            <span key={seg.index}>{seg.text}</span>
          )
        )}
      </div>

      {phrases.length > 0 && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs font-medium text-slate-500">
              {phrases.length} warning sign{phrases.length === 1 ? '' : 's'} highlighted — tap any highlighted phrase to read why
            </p>
          </div>

          {selectedPhrase && (
            <div className="rounded-xl border border-slate-200 bg-white p-4">
              <div className="flex items-start gap-3">
                <AlertCircle
                  className={`mt-0.5 h-5 w-5 shrink-0 ${
                    selectedPhrase.severity === 'high'
                      ? 'text-red-600'
                      : selectedPhrase.severity === 'medium'
                      ? 'text-amber-600'
                      : 'text-blue-600'
                  }`}
                />
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <span className="font-semibold text-slate-900">{selectedPhrase.tactic}</span>
                    <span aria-hidden="true">·</span>
                    <span className="capitalize">{selectedPhrase.severity} concern</span>
                  </div>
                  <p className="font-mono text-xs text-slate-700 break-all">
                    &ldquo;{selectedPhrase.phrase}&rdquo;
                  </p>
                  <p className="text-sm text-slate-700 leading-relaxed">{selectedPhrase.reason}</p>
                </div>
              </div>
            </div>
          )}

          {phrases.length > 1 && (
            <div className="grid gap-2 sm:grid-cols-2">
              {phrases.map((item, idx) => {
                const active = selectedPhrase?.phrase === item.phrase;
                return (
                  <button
                    key={`${item.phrase}_${idx}`}
                    type="button"
                    onClick={() => setSelectedPhrase(item)}
                    className={`flex flex-col items-start rounded-lg border p-3 text-left transition-colors min-h-[44px] focus-visible:outline-2 focus-visible:outline-blue-600 ${
                      active
                        ? 'border-blue-600 bg-blue-50/50'
                        : 'border-slate-200 bg-white hover:bg-slate-50'
                    }`}
                  >
                    <span className="text-xs font-semibold text-slate-900">{item.tactic}</span>
                    <span className="mt-0.5 line-clamp-1 font-mono text-xs text-slate-500">
                      {item.phrase}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
