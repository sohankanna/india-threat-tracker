// Run: node --experimental-strip-types --test matcher/test/
// Synthetic records and inventories only. Each case from the Phase 2 plan
// (section 1.8) is labelled "plan:".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as m from '../exposure.ts';

type Rec = m.AffectedRecord;
type Kev = m.KevEntry;

const HEADER = 'asset_id,vendor,product,version,cpe,internet_exposed,criticality,environment';

function kev(cve: string, vendor: string, product: string, extra: Partial<Kev> = {}): Kev {
  return { cve, vendor, product, date_added: '2026-01-01', due_date: '2026-01-22', required_action: 'Apply updates.', known_ransomware: false, epss: 0.5, epss_date: '2026-10-19', ...extra };
}

function rec(cve: string, products: Partial<m.AffectedProduct>[]): Rec {
  return {
    cve,
    record_state: 'PUBLISHED',
    record_updated: '2026-01-01T00:00:00Z',
    products: products.map((p) => ({ source: 'cna', vendor: '', product: '', default_status: 'unknown', versions: [], ...p })),
  };
}

function run(rows: string[], kevs: Kev[], recs: Rec[]) {
  return m.buildReport([HEADER, ...rows].join('\n'), kevs, recs, { kev_generated_at: null, affected_generated_from: null });
}

function only(report: m.Report, cve: string): m.Finding | undefined {
  return report.findings.find((f) => f.cve === cve);
}

// A product with two distinct vulnerable ranges.
const ACME = rec('CVE-2026-1000', [{
  vendor: 'Acme', product: 'Gateway Server',
  versions: [
    { version: '2.0.0', less_than: '2.4.3', status: 'affected' },
    { version: '3.0.0', less_than: '3.1.1', status: 'affected' },
  ],
}]);
const ACME_KEV = kev('CVE-2026-1000', 'Acme', 'Gateway Server');

test('plan: version inside an affected range is an affected-version match with the exact evidence', () => {
  const r = run(['gw1,Acme,Gateway Server,2.4.2,,no,medium,prod'], [ACME_KEV], [ACME]);
  const f = only(r, 'CVE-2026-1000')!;
  assert.equal(f.status, 'affected');
  assert.deepEqual(f.evidence, ['within 2.0.0 < 2.4.3']);
  assert.deepEqual(f.affected_ranges, ['2.0.0 < 2.4.3', '3.0.0 < 3.1.1']);
  assert.equal(f.identity, 'vendor and product name (Acme Gateway Server)');
});

test('plan: version outside every range is no match, and says so without claiming safety', () => {
  const r = run(['gw1,Acme,Gateway Server,2.4.3,,no,medium,prod'], [ACME_KEV], [ACME]);
  assert.equal(only(r, 'CVE-2026-1000'), undefined);
  assert.equal(r.summary['no-match'], 1);
  assert.match(r.scope, /not proof that an asset has no vulnerabilities/);
  const nm = m.matchAsset(m.readInventory([HEADER, 'gw1,Acme,Gateway Server,2.4.3,,no,medium,prod'].join('\n')).assets[0],
    [ACME_KEV], new Map([[ACME.cve, ACME]]), { includeNoMatch: true });
  assert.equal(nm[0].status, 'no-match');
});

test('plan: multiple distinct vulnerable ranges are each honoured', () => {
  for (const [v, expected] of [['2.1.0', 'affected'], ['2.9.0', undefined], ['3.0.5', 'affected'], ['3.1.1', undefined]] as const) {
    const f = only(run([`gw1,Acme,Gateway Server,${v},,no,medium,prod`], [ACME_KEV], [ACME]), 'CVE-2026-1000');
    assert.equal(f?.status, expected, v);
  }
});

test('plan: exact product with an unknown version is a candidate, never affected', () => {
  const r = run(['gw1,Acme,Gateway Server,,,yes,high,prod'], [ACME_KEV], [ACME]);
  const f = only(r, 'CVE-2026-1000')!;
  assert.equal(f.status, 'candidate');
  assert.match(f.evidence[0], /no installed version supplied/);
  assert.ok(r.issues.some((i) => i.row === 1 && /No version/.test(i.message)));
});

test('plan: ambiguous vendor/product identity is insufficient evidence', () => {
  const partial = only(run(['gw1,Acme,Gateway,2.4.2,,no,medium,prod'], [ACME_KEV], [ACME]), 'CVE-2026-1000')!;
  assert.equal(partial.status, 'insufficient');
  assert.equal(partial.tier, 'P4');
  const noVendor = only(run(['gw1,,Gateway Server,2.4.2,,no,medium,prod'], [ACME_KEV], [ACME]), 'CVE-2026-1000')!;
  assert.equal(noVendor.status, 'insufficient');
  // A different vendor with the same product name is not a match at all.
  assert.equal(only(run(['gw1,Other Corp,Gateway Server,2.4.2,,no,medium,prod'], [ACME_KEV], [ACME]), 'CVE-2026-1000'), undefined);
});

test('plan: missing product (and no CPE) is a reported error, not a silent drop', () => {
  const r = run(['gw1,Acme,,2.4.2,,no,medium,prod', 'gw2,Acme,Gateway Server,2.4.2,,no,medium,prod'], [ACME_KEV], [ACME]);
  assert.ok(r.issues.some((i) => i.row === 1 && i.level === 'error' && /Needs a product/.test(i.message)));
  assert.equal(r.summary.assets, 1);
});

test('plan: CPE-based match and CPE mismatch', () => {
  const record = rec('CVE-2026-2000', [{
    vendor: 'Example Networks', product: 'EdgeOS',
    cpes: ['cpe:2.3:o:examplenet:edgeos:5.1.0:*:*:*:*:*:*:*', 'cpe:2.3:o:examplenet:edgeos:5.1.1:*:*:*:*:*:*:*'],
  }]);
  const k = kev('CVE-2026-2000', 'Example Networks', 'EdgeOS');
  const hit = only(run([',,,,cpe:2.3:o:examplenet:edgeos:5.1.1:*:*:*:*:*:*:*,yes,high,prod'], [k], [record]), 'CVE-2026-2000')!;
  assert.equal(hit.status, 'affected');
  assert.match(hit.identity, /CPE vendor:product examplenet:edgeos/);
  assert.deepEqual(hit.evidence, ["listed in the record's CPEs (5.1.1)"]);
  const otherVersion = run([',,,,cpe:2.3:o:examplenet:edgeos:5.2.0:*:*:*:*:*:*:*,yes,high,prod'], [k], [record]);
  assert.equal(only(otherVersion, 'CVE-2026-2000'), undefined);
  const mismatch = run([',,,,cpe:2.3:o:othervendor:edgeos:5.1.1:*:*:*:*:*:*:*,yes,high,prod'], [k], [record]);
  assert.equal(only(mismatch, 'CVE-2026-2000'), undefined, 'a CPE for another vendor must not match');
});

test('plan: missing EPSS stays null, sorts after scored findings, and does not change the tier', () => {
  const recs = [ACME, rec('CVE-2026-1001', [{ vendor: 'Acme', product: 'Gateway Server', versions: [{ version: '2.0.0', less_than: '9.0', status: 'affected' }] }])];
  const kevs = [kev('CVE-2026-1000', 'Acme', 'Gateway Server', { epss: null, epss_date: null }), kev('CVE-2026-1001', 'Acme', 'Gateway Server', { epss: 0.1 })];
  const r = run(['gw1,Acme,Gateway Server,2.4.2,,no,medium,prod'], kevs, recs);
  assert.deepEqual(r.findings.map((f) => [f.cve, f.epss, f.tier]), [['CVE-2026-1001', 0.1, 'P2'], ['CVE-2026-1000', null, 'P2']]);
});

test('plan: exposure and criticality set the tier, and every tier explains itself', () => {
  const tier = (row: string, extra: Partial<Kev> = {}) => only(run([row], [kev('CVE-2026-1000', 'Acme', 'Gateway Server', extra)], [ACME]), 'CVE-2026-1000')!;
  const exposed = tier('a,Acme,Gateway Server,2.4.2,,yes,low,prod');
  assert.equal(exposed.tier, 'P1');
  assert.match(exposed.why, /internet-exposed/);
  assert.equal(tier('a,Acme,Gateway Server,2.4.2,,no,critical,prod').tier, 'P1');
  assert.equal(tier('a,Acme,Gateway Server,2.4.2,,no,low,prod', { known_ransomware: true }).tier, 'P1');
  const internal = tier('a,Acme,Gateway Server,2.4.2,,no,high,prod');
  assert.equal(internal.tier, 'P2');
  assert.match(tier('a,Acme,Gateway Server,2.4.2,,unknown,high,prod').why, /Would be P1 if internet-exposed/);
  assert.equal(tier('a,Acme,Gateway Server,,,yes,low,prod').tier, 'P2'); // candidate, exposed
  assert.equal(tier('a,Acme,Gateway Server,,,no,low,prod').tier, 'P3'); // candidate, internal
});

test('plan: invalid and malformed CSV input is reported row by row', () => {
  const bad = m.readInventory([
    HEADER,
    'a,Acme,Gateway Server,1.0,,maybe,high,prod',
    'b,Acme,Gateway Server,1.0,,yes,urgent,prod',
    'c,Acme,Gateway Server,1.0,not-a-cpe,yes,high,prod',
    'd,Acme,Gateway Server,1.0,,yes,high',
    'e,Acme,Gateway Server,1.0,,yes,high,prod',
    'e,Acme,Gateway Server,2.0,,yes,high,prod',
  ].join('\n'));
  const msgs = bad.issues.map((i) => `${i.row}:${i.level}`);
  assert.deepEqual(msgs, ['1:error', '2:error', '3:error', '4:error', '6:warning']);
  assert.equal(bad.assets.length, 2, 'both rows with the duplicate id are still processed');
  assert.match(bad.issues[3].message, /Has 7 fields; the header has 8/);
  assert.deepEqual(m.readInventory('a,"unclosed\n').issues.map((i) => i.level), ['error']);
  assert.match(m.readInventory('').issues[0].message, /empty/);
  assert.match(m.readInventory('name,owner\nx,y').issues.find((i) => i.level === 'error')!.message, /needs a "product" column/);
  const quoted = m.readInventory(`${HEADER}\n"a,1","Acme, Inc.","Gateway ""Server""",1.0,,yes,high,"multi\nline"`);
  assert.equal(quoted.assets[0].asset_id, 'a,1');
  assert.equal(quoted.assets[0].product, 'Gateway "Server"');
  assert.equal(m.readInventory(`﻿${HEADER}\na,Acme,X,1,,yes,high,p`).assets.length, 1);
});

// ── Version schemes and record shapes seen in real KEV records ──

test('version parsing: comparable schemes only', () => {
  assert.deepEqual(m.parseVersion('10.2.9-h1'), [10, 2, 9, 1]);
  assert.deepEqual(m.parseVersion('22.7R2.3'), [22, 7, 2, 3]);
  assert.deepEqual(m.parseVersion('14.1-73.41'), [14, 1, 73, 41]);
  assert.deepEqual(m.parseVersion('v1.2.3'), [1, 2, 3]);
  for (const v of ['Hotfix-BIGIP-21.1.0.2.0.30.22-ENG', '14.1-73.41 FIPS', 'Patch version 10.2 and later', '1.0.0-beta', '*', 'n/a', '']) {
    assert.equal(m.parseVersion(v), null, v);
  }
  assert.equal(m.compareVersions([7, 4], [7, 4, 0]), 0);
  assert.equal(m.compareVersions([12, 1, 10], [12, 1, 10, 2]), -1);
});

test('PAN-OS hotfix change points apply per maintenance branch', () => {
  const r = rec('CVE-2026-3000', [{ vendor: 'Palo Alto Networks', product: 'PAN-OS', versions: [
    { version: '12.1.0', less_than: '12.1.10-h2', status: 'affected', changes: [
      { at: '12.1.4-h12', status: 'unaffected' }, { at: '12.1.7-h8', status: 'unaffected' }, { at: '12.1.10-h2', status: 'unaffected' }] },
  ] }]);
  const k = kev('CVE-2026-3000', 'Palo Alto Networks', 'PAN-OS');
  const status = (v: string) => only(run([`fw,Palo Alto,PAN-OS,${v},,yes,high,prod`], [k], [r]), 'CVE-2026-3000')?.status;
  assert.equal(status('12.1.4-h11'), 'affected');
  assert.equal(status('12.1.4-h12'), undefined);
  assert.equal(status('12.1.7-h9'), undefined);
  assert.equal(status('12.1.5'), 'candidate', 'no fix listed for 12.1.5: uncertain, not fixed');
  assert.equal(status('12.1.10-h2'), undefined);
});

test('Citrix branch + build ranges, and per-branch open-ended fixes', () => {
  const r = rec('CVE-2026-4000', [{ vendor: 'NetScaler', product: 'ADC', versions: [
    { version: '13.1', less_than: '49.15', status: 'affected' },
    { version: '14.1', less_than: '12.35', status: 'affected' },
  ] }]);
  const k = kev('CVE-2026-4000', 'Citrix', 'NetScaler ADC');
  const status = (v: string) => only(run([`adc,Citrix,NetScaler ADC,${v},,yes,high,prod`], [k], [r]), 'CVE-2026-4000')?.status;
  assert.equal(status('13.1-49.14'), 'affected');
  assert.equal(status('13.1-49.15'), undefined);
  assert.equal(status('14.1-12.30'), 'affected');
  assert.equal(status('14.1-60.10'), undefined, '14.1 is not inside "13.1 < 49.15"');
  assert.equal(status('14.1'), 'candidate', 'a branch without a build cannot be placed');

  const open = rec('CVE-2026-4001', [{ vendor: 'NetScaler', product: 'ADC', versions: [
    { version: '0', less_than: '14.1-73.41', status: 'affected' },
    { version: '0', less_than: '13.1-64.28', status: 'affected' },
  ] }]);
  const k2 = kev('CVE-2026-4001', 'Citrix', 'NetScaler ADC');
  const s2 = (v: string) => only(run([`adc,Citrix,NetScaler ADC,${v},,yes,high,prod`], [k2], [open]), 'CVE-2026-4001')?.status;
  assert.equal(s2('13.1-65.0'), undefined, 'fixed on 13.1 even though it is below 14.1-73.41');
  assert.equal(s2('13.1-60.0'), 'affected');
  assert.equal(s2('14.1-73.40'), 'affected');
  assert.equal(s2('12.1-55.0'), 'candidate', 'no fix listed for 12.1');
});

test('inverted and non-comparable record ranges never produce a verdict', () => {
  const r = rec('CVE-2026-5000', [{ vendor: 'Acme', product: 'Gateway Server', versions: [
    { version: '22.0.10', less_than: '2.1.1', status: 'affected' },
    { version: '21.1.0', less_than: 'Hotfix-21.1.0.2-ENG', status: 'affected' },
  ] }]);
  const f = only(run(['a,Acme,Gateway Server,21.5.0,,yes,high,prod'], [kev('CVE-2026-5000', 'Acme', 'Gateway Server')], [r]), 'CVE-2026-5000')!;
  assert.equal(f.status, 'candidate');
  assert.ok(f.evidence.some((e) => /upper bound below its lower bound/.test(e)));
});

test('defaultStatus affected with only fixed versions listed stays a candidate', () => {
  const r = rec('CVE-2026-6000', [{ vendor: 'Ivanti', product: 'Connect Secure', default_status: 'affected', versions: [
    { version: '22.7R2.14', status: 'unaffected' }, { version: '22.8R2.5', status: 'unaffected' }] }]);
  const k = kev('CVE-2026-6000', 'Ivanti', 'Connect Secure');
  assert.equal(only(run(['v,Pulse Secure,Pulse Connect Secure,22.7R2.3,,yes,high,prod'], [k], [r]), 'CVE-2026-6000')!.status, 'candidate');
  assert.equal(only(run(['v,Ivanti,Connect Secure,22.7R2.14,,yes,high,prod'], [k], [r]), 'CVE-2026-6000'), undefined);
});

test('reviewed aliases and vendor-prefixed product names', () => {
  assert.equal(m.productKey('Fortinet', 'FortiGate'), m.productKey('Fortinet', 'FortiOS'));
  assert.equal(m.productKey('Microsoft', 'Microsoft SharePoint Server 2019'), m.productKey('Microsoft', 'SharePoint Server 2019'));
  assert.equal(m.vendorKey('Palo Alto'), m.vendorKey('Palo Alto Networks'));
  assert.notEqual(m.productKey('Microsoft', 'SharePoint Server'), m.productKey('Microsoft', 'SharePoint Server 2019'));
});

test('a record that names the product differently falls back to the KEV listing as a candidate', () => {
  const r = rec('CVE-2016-0001', [{ vendor: 'n/a', product: 'n/a', versions: [{ version: 'n/a', status: 'affected' }] }]);
  const f = only(run(['x,Acme,Gateway Server,1.0,,yes,high,prod'], [kev('CVE-2016-0001', 'Acme', 'Gateway Server')], [r]), 'CVE-2016-0001')!;
  assert.equal(f.status, 'candidate');
  assert.equal(f.record_source, 'kev');
});

test('CPE update field carries the PAN-OS hotfix; a different hotfix is not the base release', () => {
  const r = rec('CVE-2026-7000', [{ vendor: 'Palo Alto Networks', product: 'PAN-OS', cpes: [
    'cpe:2.3:o:paloaltonetworks:pan-os:10.2.10:h1:*:*:*:*:*:*',
    'cpe:2.3:o:paloaltonetworks:pan-os:10.2.10:h2:*:*:*:*:*:*',
    'cpe:2.3:o:paloaltonetworks:pan-os:10.2.11:-:*:*:*:*:*:*',
    'cpe:2.3:o:paloaltonetworks:pan-os:10.2.12:beta:*:*:*:*:*:*'] }]);
  const k = kev('CVE-2026-7000', 'Palo Alto Networks', 'PAN-OS');
  const status = (v: string) => only(run([`fw,Palo Alto Networks,PAN-OS,${v},,yes,high,prod`], [k], [r]), 'CVE-2026-7000')?.status;
  assert.equal(status('10.2.10-h1'), 'affected');
  assert.equal(status('10.2.10-h3'), undefined, 'a hotfix the record does not list');
  assert.equal(status('10.2.11'), 'affected');
  assert.equal(status('10.2.12'), undefined, 'an unrecognised update value is never read as the base release');
  const f = only(run(['fw,Palo Alto Networks,PAN-OS,10.2.10-h1,,yes,high,prod'], [k], [r]), 'CVE-2026-7000')!;
  assert.deepEqual(f.affected_ranges, ['CPE-listed versions: 10.2.10-h1, 10.2.10-h2, 10.2.11']);
  assert.deepEqual(f.evidence, ["listed in the record's CPEs (10.2.10-h1)"]);
});

// ── Exports ──

test('CSV export neutralises spreadsheet formulas and is deterministic', () => {
  const r = run(['"=HYPERLINK(""http://x"")",Acme,Gateway Server,2.4.2,,yes,high,+cmd'], [ACME_KEV], [ACME]);
  assert.equal(r.findings.length, 1);
  const csv = m.toCsv(r.findings);
  assert.ok(csv.includes(`"'=HYPERLINK(""http://x"")"`));
  assert.ok(csv.includes(",'+cmd,"));
  assert.ok(!/(^|,)[=+@]/m.test(csv.split('\n').slice(1).join('\n').replace(/"'[^"]*"/g, '')));
  assert.equal(m.toCsv(run(['"=HYPERLINK(""http://x"")",Acme,Gateway Server,2.4.2,,yes,high,+cmd'], [ACME_KEV], [ACME]).findings), csv);
  assert.equal(csv.split('\n')[0], m.EXPORT_COLUMNS.join(','));
});

test('JSON export carries the scope, issues and findings', () => {
  const r = run(['gw1,Acme,Gateway Server,2.4.2,,yes,high,prod', 'bad,Acme,,1.0,,yes,high,prod'], [ACME_KEV], [ACME]);
  const j = JSON.parse(m.toJson(r));
  assert.equal(j.report, 'india-threat-tracker-exposure');
  assert.equal(j.matcher_version, m.MATCHER_VERSION);
  assert.equal(j.findings.length, 1);
  assert.equal(j.issues.length, 1);
  assert.match(j.scope, /CISA KEV CVEs only/);
});
