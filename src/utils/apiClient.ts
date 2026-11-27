export async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const contentType = res.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    if (res.status === 404 || res.status === 405) {
      throw new Error(
        'Live AI server routes (/api/*) are unavailable on static hosting like GitHub Pages. Run the full-stack server or Cloud Run deployment to use live Gemini AI scanning.'
      );
    }
    throw new Error(`Unexpected server response (${res.status}). Please try again.`);
  }

  const data = (await res.json()) as T & { error?: string };
  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status}).`);
  }

  return data;
}
