import { useEffect, useRef, useState } from 'react';
import { motion } from 'motion/react';
import { Loader2, Send, ShieldCheck, User } from 'lucide-react';
import type { ChatMessage, ScanResult } from '../types/scam';
import { postJson } from '../utils/apiClient';

interface SafetyChatbotProps {
  activeScanContext: ScanResult | null;
  onClearContext: () => void;
}

const STARTER_PROMPTS = [
  'I already clicked a suspicious link. What should I do right now?',
  'How can I tell if a text from my bank is real or fake?',
  'Someone asked me to pay a job fee with a gift card. Is that a scam?',
  'What does a lookalike web link look like?',
];

export function SafetyChatbot({ activeScanContext, onClearContext }: SafetyChatbotProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome_1',
      role: 'assistant',
      content:
        'Hello! I am your ScamShield Safety Assistant. If you received a confusing message, clicked a link by mistake, or just want to double-check something, ask me in plain words. I am here to help.',
      timestamp: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isSending]);

  const sendMessage = async (textOverride?: string) => {
    const content = (textOverride ?? input).trim();
    if (!content || isSending) return;

    const userMsg: ChatMessage = {
      id: `user_${Date.now()}`,
      role: 'user',
      content,
      timestamp: new Date().toISOString(),
    };

    const nextMessages = [...messages, userMsg];
    setMessages(nextMessages);
    if (!textOverride) setInput('');
    setErrorMsg(null);
    setIsSending(true);

    try {
      const data = await postJson<{ reply: string }>('/api/chat', {
        messages: nextMessages.map((m) => ({ role: m.role, content: m.content })),
        activeScanContext: activeScanContext
          ? {
              channel: activeScanContext.channel,
              riskLevel: activeScanContext.riskLevel,
              scamCategory: activeScanContext.scamCategory,
              headline: activeScanContext.headline,
              extractedText: activeScanContext.extractedText,
            }
          : null,
      });

      const assistantMsg: ChatMessage = {
        id: `assistant_${Date.now()}`,
        role: 'assistant',
        content: data.reply,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Unable to send message right now.');
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          AI Safety Assistant
        </h1>
        <p className="text-sm text-slate-600 mt-1">
          Ask any question about suspicious messages, online fraud, or immediate steps if you already clicked.
        </p>
      </div>

      {activeScanContext && (
        <div className="rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs text-slate-800">
            <span className="font-bold text-blue-900">Discussing your recent scan: </span>
            <span>{activeScanContext.headline}</span>
            <span className="text-slate-500"> ({activeScanContext.riskLevel} Risk)</span>
          </div>
          <button
            type="button"
            onClick={onClearContext}
            className="text-xs font-semibold text-blue-800 hover:underline cursor-pointer"
          >
            Clear Scan Context
          </button>
        </div>
      )}

      <div className="rounded-2xl border border-slate-200 bg-white flex flex-col h-[540px] overflow-hidden">
        {/* Chat Transcript */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.18, ease: 'easeOut' }}
              className={`flex items-start gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
            >
              <div
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${
                  msg.role === 'assistant'
                    ? 'border-blue-200 bg-blue-50 text-blue-700'
                    : 'border-slate-200 bg-slate-100 text-slate-700'
                }`}
              >
                {msg.role === 'assistant' ? (
                  <ShieldCheck className="h-4 w-4" />
                ) : (
                  <User className="h-4 w-4" />
                )}
              </div>
              <div
                className={`max-w-[82%] rounded-2xl px-4 py-3 text-sm leading-relaxed whitespace-pre-wrap ${
                  msg.role === 'assistant'
                    ? 'border border-slate-200 bg-slate-50 text-slate-800'
                    : 'bg-blue-700 text-white'
                }`}
              >
                {msg.content}
              </div>
            </motion.div>
          ))}

          {isSending && (
            <div className="flex items-start gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-blue-200 bg-blue-50 text-blue-700">
                <ShieldCheck className="h-4 w-4" />
              </div>
              <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600 inline-flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin" />
                Thinking through safe steps...
              </div>
            </div>
          )}
          <div ref={endRef} />
        </div>

        {/* Starter Prompts */}
        <div className="border-t border-slate-100 bg-slate-50/70 px-4 py-2.5 flex flex-wrap gap-2">
          {STARTER_PROMPTS.map((q) => (
            <button
              key={q}
              type="button"
              disabled={isSending}
              onClick={() => sendMessage(q)}
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
            >
              {q}
            </button>
          ))}
        </div>

        {errorMsg && (
          <div className="border-t border-red-200 bg-red-50 px-4 py-2 text-xs text-red-800">
            {errorMsg}
          </div>
        )}

        {/* Compose Bar */}
        <div className="border-t border-slate-200 bg-white p-3 flex items-center gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') sendMessage();
            }}
            placeholder="Ask a question (e.g., I gave them my email address, am I safe?)"
            className="flex-1 rounded-xl border border-slate-300 bg-slate-50 px-4 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none min-h-[44px]"
          />
          <motion.button
            type="button"
            whileTap={{ scale: 0.97 }}
            disabled={isSending || !input.trim()}
            onClick={() => sendMessage()}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-700 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-50 transition-colors min-h-[44px] whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Send className="h-4 w-4" />
            Send
          </motion.button>
        </div>
      </div>
    </div>
  );
}
