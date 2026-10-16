// Drop into your blog as lib/tracker.ts
// Reads the India Threat Tracker feeds straight from the public repo so the
// page refreshes without a redeploy. Fails soft: returns empty on any error.

const RAW =
  'https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data';

export type Source = { title: string; url: string };

export type ExploitedCve = {
  cve: string; vendor: string; product: string; name: string;
  description?: string; date_added: string; due_date?: string | null;
  known_ransomware?: boolean; epss?: number | null;
  india_relevance: 'high' | 'medium' | 'global'; watchlist?: boolean;
  sources: Source[];
};

export type SmishingItem = {
  id: string; title: string; summary?: string; status?: string;
  lure_themes?: string[]; impersonates?: string[]; capabilities?: string[];
  iocs?: Record<string, string[]>; india_relevance: string;
  references_blog?: string; sources: Source[];
};

export type AptItem = {
  id: string; actor: string; aliases?: string[]; suspected_origin?: string;
  summary?: string; status?: string; targets?: string[];
  known_tools?: string[]; typical_vectors?: string[]; sources: Source[];
};

async function feed<T>(file: string): Promise<{ generated_at: string | null; items: T[] }> {
  try {
    const res = await fetch(`${RAW}/${file}`, { next: { revalidate: 3600 } });
    if (!res.ok) throw new Error(String(res.status));
    const data = await res.json();
    return { generated_at: data.generated_at ?? null, items: data.items ?? [] };
  } catch {
    return { generated_at: null, items: [] };
  }
}

export const getExploited = () => feed<ExploitedCve>('exploited-cve.json');
export const getSmishing = () => feed<SmishingItem>('smishing-apk.json');
export const getApt = () => feed<AptItem>('apt-campaigns.json');
