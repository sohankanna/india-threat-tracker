// Local Exposure Matcher: the same engine as the website, run on your machine.
//
//   node --experimental-strip-types matcher/cli.ts inventory.csv
//   node --experimental-strip-types matcher/cli.ts inventory.csv --json report.json --csv findings.csv
//   node --experimental-strip-types matcher/cli.ts inventory.csv --data path/to/data
//
// Reads data/exploited-cve.json and data/kev-affected.json from a clone of the
// repository (or --data). It makes no network requests: your inventory never
// leaves this process. Node.js 22.6 or later.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildReport, toCsv, toJson } from './exposure.ts';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
}

const input = process.argv[2];
if (!input || input.startsWith('--')) {
  console.error('usage: node --experimental-strip-types matcher/cli.ts inventory.csv [--json out.json] [--csv out.csv] [--data dir]');
  process.exit(2);
}
const dataDir = arg('--data') ?? join(import.meta.dirname, '..', 'data');
const kevFeed = JSON.parse(readFileSync(join(dataDir, 'exploited-cve.json'), 'utf8'));
const affected = JSON.parse(readFileSync(join(dataDir, 'kev-affected.json'), 'utf8'));
const report = buildReport(readFileSync(input, 'utf8'), kevFeed.items, affected.items, {
  kev_generated_at: kevFeed.generated_at ?? null,
  affected_generated_from: affected.kev_generated_at ?? null,
});

const jsonOut = arg('--json');
const csvOut = arg('--csv');
if (jsonOut) writeFileSync(jsonOut, toJson(report));
if (csvOut) writeFileSync(csvOut, toCsv(report.findings));

const s = report.summary;
console.log(`${s.assets} assets checked against ${kevFeed.items.length} KEV CVEs`);
console.log(`  affected-version matches: ${s.affected}   candidates: ${s.candidate}   insufficient evidence: ${s.insufficient}`);
console.log(`  assets with no match: ${s['no-match']}  (${report.scope})`);
for (const i of report.issues) console.log(`  ${i.level}${i.row != null ? ` row ${i.row}` : ''}: ${i.message}`);
if (!jsonOut && !csvOut) {
  for (const f of report.findings.slice(0, 25)) {
    console.log(`${f.tier} ${f.status.padEnd(12)} ${f.asset_id.padEnd(14)} ${f.cve.padEnd(16)} ${f.evidence[0]}`);
  }
  if (report.findings.length > 25) console.log(`… ${report.findings.length - 25} more; use --csv or --json for all of them`);
}
process.exit(report.issues.some((i) => i.level === 'error') ? 1 : 0);
