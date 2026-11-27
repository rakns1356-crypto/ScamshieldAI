import { useMemo, useState } from 'react';
import { motion } from 'motion/react';
import {
  AlertTriangle,
  FileText,
  Globe,
  Image as ImageIcon,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { RiskLevel, ScanChannel, ScanResult } from '../types/scam';
import { ScamThreatHeatmap } from './ScamThreatHeatmap';

interface PhishingDashboardProps {
  history: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
  onStartNewScan: (channel: ScanChannel) => void;
}

export function PhishingDashboard({
  history,
  onSelectScan,
  onStartNewScan,
}: PhishingDashboardProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<'All' | RiskLevel>('All');
  const [channelFilter, setChannelFilter] = useState<'All' | ScanChannel>('All');

  const stats = useMemo(() => {
    const total = history.length;
    const high = history.filter((h) => h.riskLevel === 'High').length;
    const medium = history.filter((h) => h.riskLevel === 'Medium').length;
    const low = history.filter((h) => h.riskLevel === 'Low').length;
    const urlChecks = history.filter((h) => h.channel === 'url' || Boolean(h.urlAnalysis)).length;

    const tacticCounts = new Map<string, number>();
    for (const item of history) {
      for (const phrase of item.suspiciousPhrases) {
        const key = phrase.tactic || 'Warning Sign';
        tacticCounts.set(key, (tacticCounts.get(key) || 0) + 1);
      }
    }

    const topTactics = Array.from(tacticCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    return { total, high, medium, low, urlChecks, topTactics };
  }, [history]);

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return history.filter((item) => {
      if (riskFilter !== 'All' && item.riskLevel !== riskFilter) return false;
      if (channelFilter !== 'All' && item.channel !== channelFilter) return false;
      if (!q) return true;
      return (
        item.headline.toLowerCase().includes(q) ||
        item.scamCategory.toLowerCase().includes(q) ||
        item.inputSummary.toLowerCase().includes(q)
      );
    });
  }, [history, searchQuery, riskFilter, channelFilter]);

  const maxTacticCount = stats.topTactics[0]?.[1] || 1;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Phishing Detection Dashboard
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Overview of your scanned messages, screenshots, and live link inspections.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onStartNewScan('url')}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Globe className="h-4 w-4" />
            Check a Link
          </button>
          <button
            type="button"
            onClick={() => onStartNewScan('screenshot')}
            className="inline-flex items-center gap-2 rounded-lg bg-blue-700 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-800 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
          >
            <ImageIcon className="h-4 w-4" />
            Scan Screenshot
          </button>
        </div>
      </div>

      {/* Unified KPI Strip */}
      <div className="rounded-2xl border border-slate-200 bg-white grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-200 overflow-hidden">
        <div className="p-5">
          <span className="text-xs font-medium text-slate-500">Total Scans</span>
          <div className="mt-2 text-2xl font-bold text-slate-900 tabular-nums">{stats.total}</div>
          <p className="mt-1 text-xs text-slate-500 tabular-nums">
            {stats.urlChecks} with link inspection
          </p>
        </div>

        <div className="p-5">
          <span className="text-xs font-medium text-red-700">High Risk Threats</span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900 tabular-nums">{stats.high}</span>
            <ShieldAlert className="h-4 w-4 text-red-600" />
          </div>
          <p className="mt-1 text-xs text-slate-500">Likely phishing or fraud</p>
        </div>

        <div className="p-5">
          <span className="text-xs font-medium text-amber-700">Medium Caution</span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900 tabular-nums">{stats.medium}</span>
            <AlertTriangle className="h-4 w-4 text-amber-600" />
          </div>
          <p className="mt-1 text-xs text-slate-500">Needs verification</p>
        </div>

        <div className="p-5">
          <span className="text-xs font-medium text-emerald-700">Low Risk / Safe</span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900 tabular-nums">{stats.low}</span>
            <ShieldCheck className="h-4 w-4 text-emerald-600" />
          </div>
          <p className="mt-1 text-xs text-slate-500">No clear red flags</p>
        </div>
      </div>

      {/* Interactive Localized D3 Scam Threat Heatmap */}
      <ScamThreatHeatmap
        userHistory={history}
        onTestInScanner={onStartNewScan}
      />

      {/* Analytics Split: Risk Distribution + Top Scam Tactics */}
      <div className="grid gap-6 lg:grid-cols-12">
        <div className="lg:col-span-5 rounded-2xl border border-slate-200 bg-white p-6 space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-900">Risk Breakdown</h2>
            <p className="text-xs text-slate-500 mt-0.5">Share of scans by safety classification</p>
          </div>

          {stats.total === 0 ? (
            <p className="text-sm text-slate-500 py-6">Run your first scan to see risk metrics.</p>
          ) : (
            <div className="space-y-4 pt-1">
              {[
                { label: 'High Risk', count: stats.high, bar: 'bg-red-600', text: 'text-red-700' },
                { label: 'Medium Risk', count: stats.medium, bar: 'bg-amber-500', text: 'text-amber-700' },
                { label: 'Low Risk', count: stats.low, bar: 'bg-emerald-600', text: 'text-emerald-700' },
              ].map((row) => {
                const pct = Math.round((row.count / stats.total) * 100);
                return (
                  <div key={row.label} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className={`font-semibold ${row.text}`}>{row.label}</span>
                      <span className="font-mono text-slate-600 tabular-nums">
                        {row.count} ({pct}%)
                      </span>
                    </div>
                    <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-100">
                      <motion.div
                        initial={{ scaleX: 0 }}
                        animate={{ scaleX: 1 }}
                        transition={{ duration: 0.4, ease: 'easeOut' }}
                        className={`h-full rounded-full ${row.bar}`}
                        style={{ width: `${pct}%`, transformOrigin: 'left' }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="lg:col-span-7 rounded-2xl border border-slate-200 bg-white p-6 space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-900">Top Scam Tactics Detected</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Most frequent manipulation patterns highlighted across your scans
            </p>
          </div>

          {stats.topTactics.length === 0 ? (
            <p className="text-sm text-slate-500 py-6">
              Suspicious tactics will appear here once ScamShield identifies warning signs.
            </p>
          ) : (
            <div className="space-y-3 pt-1">
              {stats.topTactics.map(([tactic, count], idx) => {
                const widthPct = Math.max(12, Math.round((count / maxTacticCount) * 100));
                return (
                  <div key={tactic} className="grid grid-cols-12 items-center gap-3">
                    <div className="col-span-5 sm:col-span-4 truncate text-xs font-medium text-slate-800">
                      {tactic}
                    </div>
                    <div className="col-span-5 sm:col-span-6">
                      <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-100">
                        <motion.div
                          initial={{ scaleX: 0 }}
                          animate={{ scaleX: 1 }}
                          transition={{ duration: 0.35, delay: idx * 0.04, ease: 'easeOut' }}
                          className="h-full rounded-full bg-blue-600"
                          style={{ width: `${widthPct}%`, transformOrigin: 'left' }}
                        />
                      </div>
                    </div>
                    <div className="col-span-2 text-right font-mono text-xs text-slate-600 tabular-nums">
                      {count}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Live Threat Feed Table */}
      <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden">
        <div className="border-b border-slate-200 p-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-900">Recent Scan Activity</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Click any entry to inspect highlighted phrases and safety steps
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search scans..."
                className="rounded-lg border border-slate-300 bg-slate-50 py-2 pl-8 pr-3 text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none min-h-[36px]"
              />
            </div>

            <div className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 p-1">
              {(['All', 'High', 'Medium', 'Low'] as const).map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => setRiskFilter(lvl)}
                  className={`relative rounded-md px-2.5 py-1 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    riskFilter === lvl
                      ? 'text-slate-900'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {riskFilter === lvl && (
                    <motion.span
                      layoutId="dashboard-risk-filter"
                      transition={{ type: 'spring', stiffness: 420, damping: 32 }}
                      className="absolute inset-0 rounded-md bg-white shadow-xs"
                    />
                  )}
                  <span className="relative z-10">{lvl}</span>
                </button>
              ))}
            </div>

            <div className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 p-1">
              {(['All', 'message', 'screenshot', 'url'] as const).map((ch) => (
                <button
                  key={ch}
                  type="button"
                  onClick={() => setChannelFilter(ch)}
                  className={`relative rounded-md px-2.5 py-1 text-xs font-semibold capitalize transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    channelFilter === ch
                      ? 'text-slate-900'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {channelFilter === ch && (
                    <motion.span
                      layoutId="dashboard-channel-filter"
                      transition={{ type: 'spring', stiffness: 420, damping: 32 }}
                      className="absolute inset-0 rounded-md bg-white shadow-xs"
                    />
                  )}
                  <span className="relative z-10">{ch}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <p className="text-sm font-medium text-slate-700">No scans match your current filters.</p>
            <button
              type="button"
              onClick={() => {
                setSearchQuery('');
                setRiskFilter('All');
                setChannelFilter('All');
              }}
              className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 cursor-pointer"
            >
              Reset Filters
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-500">
                  <th className="py-3 px-5">Risk Verdict</th>
                  <th className="py-3 px-4">Category &amp; Summary</th>
                  <th className="py-3 px-4">Channel</th>
                  <th className="py-3 px-4">Flags</th>
                  <th className="py-3 px-5 text-right">Scanned</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm">
                {filtered.map((item) => {
                  const RiskIcon =
                    item.riskLevel === 'High'
                      ? ShieldAlert
                      : item.riskLevel === 'Medium'
                      ? AlertTriangle
                      : ShieldCheck;
                  const riskText =
                    item.riskLevel === 'High'
                      ? 'text-red-700'
                      : item.riskLevel === 'Medium'
                      ? 'text-amber-700'
                      : 'text-emerald-700';

                  const ChannelIcon =
                    item.channel === 'screenshot'
                      ? ImageIcon
                      : item.channel === 'url'
                      ? Globe
                      : FileText;

                  return (
                    <tr
                      key={item.id}
                      onClick={() => onSelectScan(item)}
                      className="hover:bg-slate-50 transition-colors cursor-pointer group"
                    >
                      <td className="py-3.5 px-5 whitespace-nowrap">
                        <div className={`inline-flex items-center gap-1.5 font-semibold text-xs ${riskText}`}>
                          <RiskIcon className="h-4 w-4 shrink-0" />
                          <span>{item.riskLevel} Risk</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 max-w-md">
                        <div className="font-semibold text-slate-900 truncate group-hover:text-blue-700 transition-colors">
                          {item.headline}
                        </div>
                        <div className="flex items-center gap-2 text-xs text-slate-500 truncate mt-0.5">
                          <span>{item.scamCategory}</span>
                          {item.isSample && (
                            <span className="text-[11px] font-medium text-slate-400">
                              (Sample)
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap text-xs text-slate-600">
                        <div className="inline-flex items-center gap-1.5 capitalize">
                          <ChannelIcon className="h-3.5 w-3.5 text-slate-400" />
                          <span>{item.channel}</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap font-mono text-xs text-slate-700 tabular-nums">
                        {item.suspiciousPhrases.length}
                      </td>
                      <td className="py-3.5 px-5 whitespace-nowrap text-right font-mono text-xs text-slate-500 tabular-nums">
                        {new Date(item.createdAt).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
