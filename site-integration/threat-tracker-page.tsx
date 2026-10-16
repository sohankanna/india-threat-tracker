// Drop into your blog as app/tracker/page.tsx (App Router).
// Uses the same utility classes as the rest of the site (accent, border, muted).
import type { Metadata } from 'next';
import Link from 'next/link';
import { getExploited, getSmishing, getApt } from '@/lib/tracker';

export const metadata: Metadata = {
  title: 'India Threat Tracker',
  description:
    'A live, machine-readable feed of threat intelligence relevant to India — actively-exploited CVEs, fake-APK campaigns and India-focused APT activity.',
  alternates: { canonical: '/tracker' },
};

export const revalidate = 3600;

const pill =
  'text-[11px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-accent/10 text-accent';

export default async function TrackerPage() {
  const [cve, apk, apt] = await Promise.all([getExploited(), getSmishing(), getApt()]);
  const watch = cve.items.filter((c) => c.watchlist && c.india_relevance === 'high').slice(0, 25);

  return (
    <div className="max-w-5xl mx-auto px-6 py-24">
      <header className="mb-10">
        <h1 className="text-4xl lg:text-5xl font-semibold text-white mb-5 border-l-4 border-accent pl-6">
          India Threat Tracker
        </h1>
        <p className="text-lg text-muted-foreground leading-relaxed max-w-2xl pl-7">
          A curated, machine-readable feed of what&apos;s actually hitting Indian orgs and
          users. Pull the raw data from{' '}
          <a className="text-accent" href="https://github.com/sohankanna/india-threat-tracker">
            GitHub
          </a>
          .
        </p>
      </header>

      {/* Actively exploited */}
      <section className="mb-16">
        <h2 className="text-2xl font-semibold text-white mb-1">Actively exploited · watchlist</h2>
        <p className="text-sm text-muted-foreground mb-6">
          CISA KEV, India-relevant, enriched with EPSS.
          {cve.generated_at ? ` Updated ${cve.generated_at.slice(0, 10)}.` : ' Populating…'}
        </p>
        {watch.length === 0 ? (
          <p className="text-muted-foreground text-sm">Feed is populating — check back shortly.</p>
        ) : (
          <ul className="divide-y divide-border/40">
            {watch.map((c) => (
              <li key={c.cve} className="py-4 flex flex-wrap items-baseline gap-x-4 gap-y-1">
                <span className="font-mono text-accent w-40">{c.cve}</span>
                <span className="text-white flex-1 min-w-0">{c.vendor} {c.product}</span>
                {c.epss != null && (
                  <span className="text-xs font-mono text-muted-foreground">
                    EPSS {(c.epss * 100).toFixed(0)}%
                  </span>
                )}
                {c.known_ransomware && <span className="text-xs text-[#e66767]">ransomware</span>}
                {c.due_date && (
                  <span className="text-xs font-mono text-muted-foreground">due {c.due_date}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Fake-APK campaigns */}
      <section className="mb-16">
        <h2 className="text-2xl font-semibold text-white mb-6">Fake-APK & smishing campaigns</h2>
        <div className="grid gap-4">
          {apk.items.map((a) => (
            <div key={a.id} className="rounded-xl border border-border/50 bg-card p-5">
              <div className="flex items-center gap-3 mb-2">
                <span className={pill}>{a.status ?? 'active'}</span>
                {a.references_blog && (
                  <Link href={`/research/${a.references_blog}`} className="text-xs text-accent">
                    read the breakdown →
                  </Link>
                )}
              </div>
              <h3 className="text-lg font-semibold text-white">{a.title}</h3>
              {a.summary && (
                <p className="text-sm text-muted-foreground mt-2 leading-relaxed">{a.summary}</p>
              )}
              {a.sources?.[0] && (
                <a className="text-xs text-accent mt-3 inline-block" href={a.sources[0].url}>
                  source: {a.sources[0].title}
                </a>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* APT */}
      <section>
        <h2 className="text-2xl font-semibold text-white mb-6">India-focused APT activity</h2>
        <div className="grid gap-4">
          {apt.items.map((a) => (
            <div key={a.id} className="rounded-xl border border-border/50 bg-card p-5">
              <h3 className="text-lg font-semibold text-white">
                {a.actor}{' '}
                {a.aliases?.length ? (
                  <span className="text-sm text-muted-foreground font-normal">
                    ({a.aliases.join(', ')})
                  </span>
                ) : null}
              </h3>
              {a.summary && (
                <p className="text-sm text-muted-foreground mt-2 leading-relaxed">{a.summary}</p>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
