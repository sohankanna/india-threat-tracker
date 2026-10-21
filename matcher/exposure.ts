/**
 * India Threat Tracker: Exposure Matcher engine.
 *
 * One self-contained module with no dependencies, used unchanged by the
 * website (in the browser), the local CLI (matcher/cli.ts) and the tests
 * (node --experimental-strip-types --test matcher/test/). Nothing in here does
 * network or storage I/O: an inventory goes in, a report comes out.
 *
 * Methodology: EXPOSURE-MATCHER.md. In short:
 *   identity  - does this asset's vendor/product (or CPE) name the product a
 *               CVE record lists? Exact (after reviewed aliases) or not at all;
 *               a partial name overlap is reported as insufficient evidence.
 *   version   - compared only when both sides are plain numeric versions in a
 *               recognised scheme (dotted, dash-build, PAN-OS -hN, Ivanti RN).
 *               Anything else is "not comparable" and the finding stays a
 *               candidate. Nothing is guessed.
 *   status    - affected | candidate | insufficient | no-match.
 *   priority  - documented tiers, not a score; see priorityFor().
 */

export const MATCHER_VERSION = '1.0.0';

// ── Types ──────────────────────────────────────────────────────────────────
export type Exposure = 'yes' | 'no' | 'unknown';
export type Criticality = 'low' | 'medium' | 'high' | 'critical' | 'unspecified';

export type Asset = {
  row: number; // 1-based data row in the CSV (header excluded)
  asset_id: string;
  vendor: string;
  product: string;
  version: string;
  cpe: string;
  internet_exposed: Exposure;
  criticality: Criticality;
  environment: string;
};

export type VersionEntry = {
  version?: string;
  status?: string;
  less_than?: string;
  less_than_or_equal?: string;
  version_type?: string;
  changes?: { at: string; status: string }[];
};

export type AffectedProduct = {
  source: string;
  vendor: string;
  product: string;
  default_status: string;
  versions: VersionEntry[];
  cpes?: string[];
  platforms?: string[];
  modules?: string[];
};

export type AffectedRecord = {
  cve: string;
  record_state: string;
  record_updated: string | null;
  products: AffectedProduct[];
};

export type KevEntry = {
  cve: string;
  vendor: string;
  product: string;
  name?: string;
  date_added: string;
  due_date?: string | null;
  required_action?: string;
  known_ransomware?: boolean;
  epss?: number | null;
  epss_percentile?: number | null;
  epss_date?: string | null;
  india_relevance?: string;
};

export type Status = 'affected' | 'candidate' | 'insufficient' | 'no-match';
export type Tier = 'P1' | 'P2' | 'P3' | 'P4';

export type Finding = {
  asset_row: number;
  asset_id: string;
  vendor: string;
  product: string;
  version: string;
  cve: string;
  status: Status;
  identity: string; // how the product was matched
  evidence: string[]; // exact matching evidence, human-readable
  record_product: string; // "Vendor Product" as the CVE record names it
  record_source: string; // cna | adp:<name> | kev
  affected_ranges: string[]; // the record's ranges for that product
  kev_date_added: string;
  kev_due_date: string | null;
  required_action: string;
  known_ransomware: boolean;
  epss: number | null;
  epss_date: string | null;
  india_relevance: string;
  internet_exposed: Exposure;
  criticality: Criticality;
  environment: string;
  tier: Tier;
  why: string;
  references: string[];
};

// ── Names ──────────────────────────────────────────────────────────────────
/** Lower-case, alphanumerics only: "Palo Alto Networks" -> "paloaltonetworks". */
export function key(s: string): string {
  return (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Reviewed aliases. Each entry maps every listed spelling to one canonical key.
 * Only add an alias when the names refer to the same product line; anything
 * else must stay unmatched (see EXPOSURE-MATCHER.md, "Identity").
 */
const VENDOR_ALIASES: Record<string, string[]> = {
  paloaltonetworks: ['palo alto networks', 'palo alto', 'paloalto', 'paloaltonetworks', 'pan'],
  fortinet: ['fortinet'],
  ivanti: ['ivanti', 'pulse secure', 'pulsesecure'],
  citrix: ['citrix', 'netscaler', 'cloud software group'],
  microsoft: ['microsoft', 'microsoft corporation', 'msft'],
  cisco: ['cisco', 'cisco systems'],
  f5: ['f5', 'f5 networks'],
  vmware: ['vmware', 'broadcom vmware', 'vmware by broadcom'],
  atlassian: ['atlassian'],
  apache: ['apache', 'apache software foundation', 'the apache software foundation'],
  oracle: ['oracle'],
  sap: ['sap', 'sap se'],
  sonicwall: ['sonicwall'],
  juniper: ['juniper', 'juniper networks'],
  checkpoint: ['check point', 'checkpoint', 'check point software'],
  zyxel: ['zyxel'],
  sophos: ['sophos'],
  google: ['google'],
  apple: ['apple'],
  adobe: ['adobe'],
};

const PRODUCT_ALIASES: Record<string, string[]> = {
  panos: ['pan-os', 'panos', 'pan os'],
  fortios: ['fortios', 'fortigate'],
  connectsecure: ['connect secure', 'pulse connect secure', 'ivanti connect secure', 'ics'],
  adc: ['netscaler adc', 'citrix adc', 'adc', 'citrix netscaler adc'],
  gateway: ['netscaler gateway', 'citrix gateway', 'gateway', 'citrix netscaler gateway'],
};

function aliasIndex(table: Record<string, string[]>): Map<string, string> {
  const m = new Map<string, string>();
  for (const [canon, names] of Object.entries(table)) for (const n of names) m.set(key(n), canon);
  return m;
}
const VENDOR_INDEX = aliasIndex(VENDOR_ALIASES);
const PRODUCT_INDEX = aliasIndex(PRODUCT_ALIASES);

export function vendorKey(vendor: string): string {
  const k = key(vendor);
  return VENDOR_INDEX.get(k) ?? k;
}

/** Product key with the vendor's own name stripped from the front
 * ("Microsoft SharePoint Server 2019" -> "sharepointserver2019"). */
export function productKey(vendor: string, product: string): string {
  let p = key(product);
  const v = key(vendor);
  const vk = vendorKey(vendor);
  const prefixes = [v, ...(VENDOR_ALIASES[vk] || []).map(key)].filter((x) => x.length >= 3);
  for (const pre of prefixes.sort((a, b) => b.length - a.length)) {
    if (p.startsWith(pre) && p.length > pre.length) {
      p = p.slice(pre.length);
      break;
    }
  }
  return PRODUCT_INDEX.get(p) ?? p;
}

const UNUSABLE = new Set(['', 'na', 'n/a', 'unspecified', 'unknown', '*', '-', 'all', 'none']);

// ── CPE ────────────────────────────────────────────────────────────────────
export type Cpe = { part: string; vendor: string; product: string; version: string; update: string };

/** cpe:2.3:part:vendor:product:version:... (escaped colons are respected). */
export function parseCpe(cpe: string): Cpe | null {
  if (!cpe || !/^cpe:2\.3:[aho]:/i.test(cpe.trim())) return null;
  const parts: string[] = [];
  let cur = '';
  const s = cpe.trim();
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\' && i + 1 < s.length) {
      cur += s[i + 1]; // escaped character, kept literally
      i++;
    } else if (s[i] === ':') {
      parts.push(cur);
      cur = '';
    } else cur += s[i];
  }
  parts.push(cur);
  if (parts.length < 6) return null;
  return { part: parts[2].toLowerCase(), vendor: parts[3], product: parts[4], version: parts[5], update: parts[6] ?? '*' };
}

/**
 * The version a CPE names, including its "update" field: Palo Alto encodes
 * hotfixes there (pan-os:10.2.10:h1 is 10.2.10-h1). A numeric or hN update is
 * appended; any other update value makes the CPE version not comparable, so
 * it can never be mistaken for the base release.
 */
export function cpeVersion(c: Cpe): string | null {
  if (UNUSABLE.has(c.version)) return null;
  const u = (c.update || '*').trim();
  if (u === '*' || u === '-' || u === '') return c.version;
  if (/^h?\d+$/i.test(u)) return `${c.version}-${u.toLowerCase().startsWith('h') ? u.toLowerCase() : u}`;
  return null;
}

// ── Versions ───────────────────────────────────────────────────────────────
/**
 * A version is comparable only if it is digits joined by ".", "-", "_", or the
 * vendor tokens "-h" (PAN-OS hotfix: 10.2.9-h1) and "R" (Ivanti: 22.7R2.3),
 * optionally prefixed with "v". Everything else (F5 engineering hotfixes,
 * "14.1-73.41 FIPS", "Patch version 10.2 and later", Windows edition names) is
 * not comparable, and no ordering is invented for it.
 */
const COMPARABLE = /^v?\d+(?:(?:[._-]|-h|R)\d+)*$/i;

export function parseVersion(v: string | undefined | null): number[] | null {
  if (v == null) return null;
  const s = String(v).trim();
  if (!COMPARABLE.test(s)) return null;
  return (s.match(/\d+/g) || []).map((n) => parseInt(n, 10));
}

/** -1, 0, 1. Shorter versions are padded with zeros: 7.4 == 7.4.0, 12.1.10 < 12.1.10-h2. */
export function compareVersions(a: number[], b: number[]): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

type Verdict = { result: 'affected' | 'unaffected' | 'uncertain' | 'not-covered' | 'not-comparable'; evidence: string };

function isLowerUnbounded(v: string | undefined): boolean {
  return v == null || v === '0' || v === '*' || UNUSABLE.has(v.trim().toLowerCase());
}

/** Describe a version entry the way the record states it. */
export function describeEntry(e: VersionEntry): string {
  const from = isLowerUnbounded(e.version) ? '' : `${e.version} `;
  if (e.less_than) return `${from}< ${e.less_than}${e.status && e.status !== 'affected' ? ` (${e.status})` : ''}`.trim();
  if (e.less_than_or_equal) return `${from}<= ${e.less_than_or_equal}`.trim();
  return `${e.version ?? '?'} (${e.status ?? 'unknown'})`;
}

/**
 * Evaluate one CVE 5 version entry against a parsed asset version, following
 * the CVE JSON 5 semantics, conservatively:
 *  - range [version, lessThan) or [version, lessThanOrEqual];
 *  - "changes" inside a range are trusted only on the same maintenance branch
 *    (all components but the last equal), because vendors such as Palo Alto
 *    list hotfix points per branch (12.1.4-h12, 12.1.7-h8) and a linear reading
 *    would wrongly treat 12.1.5 as fixed. Off-branch, the result is "uncertain".
 *  - a single version with a status is an exact match.
 */
export function evaluateEntry(e: VersionEntry, asset: number[], recordVendor = ''): Verdict {
  const upperRaw = e.less_than ?? e.less_than_or_equal;
  if (upperRaw != null) {
    const unboundedUpper = upperRaw.trim() === '*';
    let upper = unboundedUpper ? null : parseVersion(upperRaw);
    const lower = isLowerUnbounded(e.version) ? [] : parseVersion(e.version);
    if ((!unboundedUpper && upper == null) || lower == null) {
      return { result: 'not-comparable', evidence: `record range "${describeEntry(e)}" is not in a comparable format` };
    }
    // Citrix/NetScaler write some ranges as branch + build: version "13.1",
    // lessThan "49.15" means builds 13.1-x below 49.15, not versions 13.1 to 49.15.
    if (vendorKey(recordVendor) === 'citrix' && upper && lower.length === 2 && upper.length === 2 &&
        compareVersions(upper, lower) !== 0 && e.version && !/[-.]\d+[-.]/.test(upperRaw)) {
      if (asset.length < 4) return { result: 'not-comparable', evidence: `the record gives builds for branch ${e.version}; supply the full build (e.g. ${e.version}-${upperRaw})` };
      if (compareVersions(asset.slice(0, 2), lower) !== 0) return { result: 'not-covered', evidence: `not branch ${e.version}` };
      const build = asset.slice(2);
      const inBuild = e.less_than != null ? compareVersions(build, upper) < 0 : compareVersions(build, upper) <= 0;
      return inBuild
        ? { result: e.status === 'unaffected' ? 'unaffected' : 'affected', evidence: `branch ${e.version}, build below ${e.less_than ? '' : 'or equal to '}${upperRaw}` }
        : { result: 'not-covered', evidence: `branch ${e.version}, build at or above ${upperRaw}` };
    }
    if (upper && lower.length && compareVersions(upper, lower) < 0) {
      return { result: 'not-comparable', evidence: `record range "${describeEntry(e)}" has an upper bound below its lower bound` };
    }
    const aboveLower = lower.length === 0 || compareVersions(asset, lower) >= 0;
    const belowUpper =
      upper == null ||
      (e.less_than != null ? compareVersions(asset, upper) < 0 : compareVersions(asset, upper) <= 0);
    if (!(aboveLower && belowUpper)) return { result: 'not-covered', evidence: `outside ${describeEntry(e)}` };
    const status = e.status === 'unaffected' ? 'unaffected' : 'affected';
    if (e.changes && e.changes.length) {
      let sameBranchDecided: Verdict | null = null;
      let offBranchFlip = false;
      for (const c of e.changes) {
        const at = parseVersion(c.at);
        if (at == null) return { result: 'uncertain', evidence: `record change point "${c.at}" is not comparable` };
        const branch = at.slice(0, Math.max(1, at.length - 1));
        const assetBranch = asset.slice(0, branch.length);
        const sameBranch = compareVersions(branch, assetBranch) === 0 && asset.length >= branch.length;
        if (sameBranch) {
          if (compareVersions(asset, at) >= 0) {
            sameBranchDecided = { result: c.status === 'unaffected' ? 'unaffected' : 'affected', evidence: `fixed on this branch at ${c.at}` };
          } else if (!sameBranchDecided) {
            sameBranchDecided = { result: status, evidence: `within ${describeEntry(e)}; this branch is fixed at ${c.at}` };
          }
        } else if (compareVersions(asset, at) >= 0 && c.status === 'unaffected') {
          offBranchFlip = true;
        }
      }
      if (sameBranchDecided) return sameBranchDecided;
      if (offBranchFlip) {
        return { result: 'uncertain', evidence: `within ${describeEntry(e)}, but the record lists no fixed release for this maintenance branch` };
      }
    }
    return { result: status, evidence: `within ${describeEntry(e)}` };
  }
  const exact = parseVersion(e.version);
  if (exact == null) return { result: 'not-comparable', evidence: `record version "${e.version ?? ''}" is not in a comparable format` };
  if (compareVersions(asset, exact) === 0) {
    return { result: e.status === 'unaffected' ? 'unaffected' : 'affected', evidence: `exactly ${e.version} (${e.status ?? 'unknown'})` };
  }
  return { result: 'not-covered', evidence: `not ${e.version}` };
}

// ── Identity ───────────────────────────────────────────────────────────────
type Identity = { level: 'exact' | 'partial' | 'none'; how: string };

function assetNames(a: Asset): { vendor: string; product: string; version: string; cpe: Cpe | null } {
  const cpe = parseCpe(a.cpe);
  return {
    vendor: a.vendor || (cpe ? cpe.vendor.replace(/_/g, ' ') : ''),
    product: a.product || (cpe ? cpe.product.replace(/_/g, ' ') : ''),
    version: a.version || (cpe ? cpeVersion(cpe) ?? '' : ''),
    cpe,
  };
}

export function identify(a: Asset, p: { vendor: string; product: string; cpes?: string[] }): Identity {
  const names = assetNames(a);
  if (names.cpe && p.cpes && p.cpes.length) {
    const want = `${key(names.cpe.vendor)}:${key(names.cpe.product)}`;
    const recordCpes = p.cpes.map(parseCpe).filter((c): c is Cpe => c != null);
    if (recordCpes.some((c) => `${key(c.vendor)}:${key(c.product)}` === want)) {
      return { level: 'exact', how: `CPE vendor:product ${names.cpe.vendor}:${names.cpe.product}` };
    }
  }
  if (!names.product || UNUSABLE.has(p.product.trim().toLowerCase())) return { level: 'none', how: '' };
  const pk = productKey(p.vendor, p.product);
  const ak = productKey(names.vendor, names.product);
  if (!ak) return { level: 'none', how: '' };
  const vendorKnown = !!names.vendor && !UNUSABLE.has(p.vendor.trim().toLowerCase());
  const sameVendor = vendorKnown && vendorKey(names.vendor) === vendorKey(p.vendor);
  if (sameVendor && pk === ak) return { level: 'exact', how: `vendor and product name (${p.vendor} ${p.product})` };
  if (sameVendor && pk.length >= 4 && ak.length >= 4 && (pk.includes(ak) || ak.includes(pk))) {
    return { level: 'partial', how: `"${names.product}" only partly matches the record's "${p.product}"` };
  }
  if (!names.vendor && pk === ak) {
    return { level: 'partial', how: `product name matches "${p.product}" but no vendor was given` };
  }
  return { level: 'none', how: '' };
}

// ── Matching ───────────────────────────────────────────────────────────────
function rangesOf(p: AffectedProduct): string[] {
  const out = p.versions.filter((v) => v.status !== 'unaffected' || v.less_than || v.less_than_or_equal).map(describeEntry);
  const cpeVersions = [...new Set((p.cpes || []).map(parseCpe).filter((c): c is Cpe => c != null).map(cpeVersion).filter((v): v is string => v != null))];
  if (cpeVersions.length) out.push(`CPE-listed versions: ${cpeVersions.slice(0, 12).join(', ')}${cpeVersions.length > 12 ? `, … (${cpeVersions.length} in all)` : ''}`);
  if (p.default_status && p.default_status !== 'unknown') out.push(`versions not listed: ${p.default_status}`);
  return out;
}

type ProductResult = { status: Status; evidence: string[] };

/** Version verdict for one record product whose identity already matched. */
export function versionVerdict(p: AffectedProduct, rawVersion: string): ProductResult {
  if (!rawVersion || UNUSABLE.has(rawVersion.trim().toLowerCase())) {
    return { status: 'candidate', evidence: ['no installed version supplied, so the affected ranges could not be checked'] };
  }
  const asset = parseVersion(rawVersion);
  if (asset == null) {
    return { status: 'candidate', evidence: [`installed version "${rawVersion}" is not in a comparable format`] };
  }
  // Several open-ended fixes on different branches ("< 14.1-73.41",
  // "< 13.1-64.28") are per-branch fixes: only the one on the asset's branch
  // (major.minor) applies. If none is, the record does not say.
  let entries = p.versions;
  const openEnded = entries.filter((e) => isLowerUnbounded(e.version) && (e.less_than ?? e.less_than_or_equal) && parseVersion(e.less_than ?? e.less_than_or_equal));
  const branchOf = (v: number[]) => v.slice(0, 2).join('.');
  const branches = new Set(openEnded.map((e) => branchOf(parseVersion((e.less_than ?? e.less_than_or_equal)!)!)));
  if (branches.size > 1) {
    const mine = openEnded.filter((e) => branchOf(parseVersion((e.less_than ?? e.less_than_or_equal)!)!) === branchOf(asset));
    if (!mine.length) {
      return { status: 'candidate', evidence: [`the record lists fixes for branches ${[...branches].sort().join(', ')}, not for ${branchOf(asset)}; check the vendor advisory`] };
    }
    entries = [...entries.filter((e) => !openEnded.includes(e)), ...mine];
  }
  const verdicts = entries.map((e) => evaluateEntry(e, asset, p.vendor));
  for (const c of (p.cpes || []).map(parseCpe)) {
    if (!c) continue;
    const named = cpeVersion(c);
    if (named == null) continue;
    const cv = parseVersion(named);
    if (cv && compareVersions(asset, cv) === 0) verdicts.push({ result: 'affected', evidence: `listed in the record's CPEs (${named})` });
    else if (cv) verdicts.push({ result: 'not-covered', evidence: `not a CPE-listed version` });
  }
  const affected = verdicts.filter((v) => v.result === 'affected');
  const unaffected = verdicts.filter((v) => v.result === 'unaffected');
  if (unaffected.length && !affected.length) {
    return { status: 'no-match', evidence: unaffected.map((v) => v.evidence) };
  }
  if (affected.length) return { status: 'affected', evidence: affected.map((v) => v.evidence) };
  const uncertain = verdicts.filter((v) => v.result === 'uncertain');
  if (uncertain.length) return { status: 'candidate', evidence: uncertain.map((v) => v.evidence) };
  const comparable = verdicts.filter((v) => v.result === 'not-covered');
  if (comparable.length) {
    if (p.default_status === 'affected') {
      return {
        status: 'candidate',
        evidence: [`${rawVersion} is not among the versions the record lists, and the record says unlisted versions are affected; check the vendor advisory`],
      };
    }
    return { status: 'no-match', evidence: [`${rawVersion} is outside every affected range the record lists`] };
  }
  return { status: 'candidate', evidence: verdicts.length ? verdicts.map((v) => v.evidence) : ['the record gives no version information for this product'] };
}

const RANK: Record<Status, number> = { affected: 0, candidate: 1, insufficient: 2, 'no-match': 3 };

export type MatchOptions = { includeNoMatch?: boolean };

/** Every finding for one asset across all KEV CVEs. */
export function matchAsset(asset: Asset, kev: KevEntry[], affected: Map<string, AffectedRecord>, opts: MatchOptions = {}): Finding[] {
  const out: Finding[] = [];
  const names = assetNames(asset);
  for (const k of kev) {
    const rec = affected.get(k.cve);
    let best: { status: Status; identity: string; evidence: string[]; product: AffectedProduct | null } | null = null;
    for (const p of rec?.products || []) {
      const id = identify(asset, p);
      if (id.level === 'none') continue;
      let res: ProductResult;
      if (id.level === 'partial') {
        res = { status: 'insufficient', evidence: [id.how] };
      } else {
        res = versionVerdict(p, names.version);
      }
      if (!best || RANK[res.status] < RANK[best.status]) best = { status: res.status, identity: id.how, evidence: res.evidence, product: p };
    }
    if (!best) {
      // The CVE record names the product differently: fall back to CISA's KEV listing.
      const id = identify(asset, { vendor: k.vendor, product: k.product });
      if (id.level === 'exact') {
        best = {
          status: 'candidate',
          identity: `CISA KEV listing (${k.vendor} ${k.product})`,
          evidence: ['the product matches the KEV listing, but the CVE record does not name it in a way that allows a version check'],
          product: null,
        };
      } else if (id.level === 'partial') {
        best = { status: 'insufficient', identity: `CISA KEV listing (${k.vendor} ${k.product})`, evidence: [id.how], product: null };
      }
    }
    if (!best || (best.status === 'no-match' && !opts.includeNoMatch)) continue;
    const f: Finding = {
      asset_row: asset.row,
      asset_id: asset.asset_id,
      vendor: names.vendor,
      product: names.product,
      version: names.version,
      cve: k.cve,
      status: best.status,
      identity: best.identity,
      evidence: best.evidence,
      record_product: best.product ? `${best.product.vendor} ${best.product.product}`.trim() : `${k.vendor} ${k.product}`,
      record_source: best.product ? best.product.source : 'kev',
      affected_ranges: best.product ? rangesOf(best.product) : [],
      kev_date_added: k.date_added,
      kev_due_date: k.due_date ?? null,
      required_action: k.required_action ?? '',
      known_ransomware: !!k.known_ransomware,
      epss: k.epss ?? null,
      epss_date: k.epss_date ?? null,
      india_relevance: k.india_relevance ?? '',
      internet_exposed: asset.internet_exposed,
      criticality: asset.criticality,
      environment: asset.environment,
      tier: 'P4',
      why: '',
      references: [
        `https://www.cve.org/CVERecord?id=${k.cve}`,
        `https://nvd.nist.gov/vuln/detail/${k.cve}`,
        'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      ],
    };
    const p = priorityFor(f);
    f.tier = p.tier;
    f.why = p.why;
    out.push(f);
  }
  return out;
}

// ── Priority ───────────────────────────────────────────────────────────────
/**
 * Transparent tiers, not a score. Every finding here is a KEV CVE, so
 * exploitation in the wild is already established; the tiers combine how
 * strong the match evidence is with the exposure and criticality the user
 * supplied. EPSS is shown and used only to order findings within a tier.
 *
 *   P1  affected-version match AND (internet-exposed OR critical asset OR
 *       known ransomware use)
 *   P2  affected-version match otherwise; or a candidate on an
 *       internet-exposed or critical asset
 *   P3  candidate otherwise
 *   P4  insufficient evidence
 */
export function priorityFor(f: Pick<Finding, 'status' | 'internet_exposed' | 'criticality' | 'known_ransomware'>): { tier: Tier; why: string } {
  const exposed = f.internet_exposed === 'yes';
  const critical = f.criticality === 'critical';
  const reasons: string[] = ['known exploited (CISA KEV)'];
  if (exposed) reasons.push('internet-exposed');
  if (critical) reasons.push('critical asset');
  if (f.known_ransomware) reasons.push('known ransomware use');
  if (f.status === 'affected') {
    if (exposed || critical || f.known_ransomware) return { tier: 'P1', why: `Version in an affected range; ${reasons.join(', ')}.` };
    const hint = f.internet_exposed === 'unknown' ? ' Would be P1 if internet-exposed.' : '';
    return { tier: 'P2', why: `Version in an affected range; ${reasons.join(', ')}.${hint}` };
  }
  if (f.status === 'candidate') {
    if (exposed || critical) return { tier: 'P2', why: `Product matches but the version could not be confirmed; ${reasons.join(', ')}. Confirm the version.` };
    return { tier: 'P3', why: `Product matches but the version could not be confirmed; ${reasons.join(', ')}.` };
  }
  if (f.status === 'insufficient') return { tier: 'P4', why: 'Only a partial product-name match; not enough evidence to call it a match.' };
  return { tier: 'P4', why: 'No affected configuration matched.' };
}

const TIER_RANK: Record<Tier, number> = { P1: 0, P2: 1, P3: 2, P4: 3 };

/** Deterministic order: tier, then EPSS (missing last), then asset row, then CVE. */
export function sortFindings(fs: Finding[]): Finding[] {
  return [...fs].sort(
    (a, b) =>
      TIER_RANK[a.tier] - TIER_RANK[b.tier] ||
      (b.epss ?? -1) - (a.epss ?? -1) ||
      a.asset_row - b.asset_row ||
      a.cve.localeCompare(b.cve),
  );
}

// ── CSV in ─────────────────────────────────────────────────────────────────
export const COLUMNS = ['asset_id', 'vendor', 'product', 'version', 'cpe', 'internet_exposed', 'criticality', 'environment'] as const;

export type Issue = { row: number | null; level: 'error' | 'warning'; message: string };

/** RFC 4180 CSV: quoted fields, doubled quotes, CRLF/LF, newlines in quotes, BOM. */
export function parseCsv(text: string): string[][] | { error: string } {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  for (; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += c;
    } else if (c === '"') {
      if (field.length) return { error: `unexpected quote inside an unquoted field on line ${rows.length + 1}` };
      quoted = true;
    } else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else field += c;
  }
  if (quoted) return { error: 'a quoted field is never closed' };
  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

const EXPOSURE_VALUES: Record<string, Exposure> = { yes: 'yes', y: 'yes', true: 'yes', no: 'no', n: 'no', false: 'no', unknown: 'unknown', '': 'unknown' };
const CRITICALITY_VALUES: Record<string, Criticality> = { low: 'low', medium: 'medium', high: 'high', critical: 'critical', '': 'unspecified' };

export const MAX_ROWS = 50000;

/** Parse and validate an inventory. Rows with errors are reported, never silently dropped. */
export function readInventory(text: string): { assets: Asset[]; issues: Issue[] } {
  const issues: Issue[] = [];
  const parsed = parseCsv(text);
  if (!Array.isArray(parsed)) return { assets: [], issues: [{ row: null, level: 'error', message: `Not a valid CSV file: ${parsed.error}.` }] };
  const lines = parsed.filter((r) => r.some((c) => c.trim() !== ''));
  if (!lines.length) return { assets: [], issues: [{ row: null, level: 'error', message: 'The file is empty.' }] };
  const header = lines[0].map((h) => h.trim().toLowerCase());
  const idx: Record<string, number> = {};
  header.forEach((h, i) => {
    if (h in idx) issues.push({ row: null, level: 'error', message: `Column "${h}" appears twice.` });
    idx[h] = i;
  });
  for (const h of header) if (h && !(COLUMNS as readonly string[]).includes(h)) issues.push({ row: null, level: 'warning', message: `Unknown column "${h}" is ignored.` });
  if (!('product' in idx) && !('cpe' in idx)) {
    issues.push({ row: null, level: 'error', message: 'The header needs a "product" column (or "cpe"). Download the template for the expected columns.' });
    return { assets: [], issues };
  }
  if (lines.length - 1 > MAX_ROWS) {
    issues.push({ row: null, level: 'error', message: `The file has ${lines.length - 1} rows; the limit is ${MAX_ROWS}.` });
    return { assets: [], issues };
  }
  const assets: Asset[] = [];
  const seenIds = new Map<string, number>();
  for (let r = 1; r < lines.length; r++) {
    const cells = lines[r];
    const row = r;
    if (cells.length !== header.length) {
      issues.push({ row, level: 'error', message: `Has ${cells.length} fields; the header has ${header.length}. Row not processed.` });
      continue;
    }
    const get = (c: string) => (c in idx ? (cells[idx[c]] ?? '').trim() : '');
    const exposedRaw = get('internet_exposed').toLowerCase();
    const critRaw = get('criticality').toLowerCase();
    let ok = true;
    if (!(exposedRaw in EXPOSURE_VALUES)) {
      issues.push({ row, level: 'error', message: `internet_exposed is "${get('internet_exposed')}"; use yes, no or unknown. Row not processed.` });
      ok = false;
    }
    if (!(critRaw in CRITICALITY_VALUES)) {
      issues.push({ row, level: 'error', message: `criticality is "${get('criticality')}"; use low, medium, high or critical. Row not processed.` });
      ok = false;
    }
    const cpe = get('cpe');
    if (cpe && !parseCpe(cpe)) {
      issues.push({ row, level: 'error', message: `cpe "${cpe}" is not a CPE 2.3 string (cpe:2.3:part:vendor:product:version:…). Row not processed.` });
      ok = false;
    }
    if (!get('product') && !cpe) {
      issues.push({ row, level: 'error', message: 'Needs a product (or a cpe). Row not processed.' });
      ok = false;
    }
    if (!ok) continue;
    if (!get('vendor') && !cpe) issues.push({ row, level: 'warning', message: 'No vendor: matches can only be partial.' });
    if (!get('version') && !(cpe && parseCpe(cpe) && !UNUSABLE.has(parseCpe(cpe)!.version))) {
      issues.push({ row, level: 'warning', message: 'No version: findings will be candidates at best.' });
    }
    const id = get('asset_id');
    if (id) {
      if (seenIds.has(id)) issues.push({ row, level: 'warning', message: `asset_id "${id}" is also used on row ${seenIds.get(id)}. Both rows are processed.` });
      else seenIds.set(id, row);
    }
    assets.push({
      row,
      asset_id: id || `row-${row}`,
      vendor: get('vendor'),
      product: get('product'),
      version: get('version'),
      cpe,
      internet_exposed: EXPOSURE_VALUES[exposedRaw],
      criticality: CRITICALITY_VALUES[critRaw],
      environment: get('environment'),
    });
  }
  return { assets, issues };
}

// ── Report ─────────────────────────────────────────────────────────────────
export type Report = {
  report: 'india-threat-tracker-exposure';
  matcher_version: string;
  data: { kev_generated_at: string | null; affected_generated_from: string | null };
  scope: string;
  summary: Record<Status, number> & { assets: number; assets_with_findings: number };
  issues: Issue[];
  findings: Finding[];
};

export const SCOPE_NOTE =
  'Checked against CISA KEV CVEs only. "No match" means no listed affected configuration matched; it is not proof that an asset has no vulnerabilities, and an affected version is not proof of compromise.';

export function buildReport(
  text: string,
  kev: KevEntry[],
  affected: AffectedRecord[],
  meta: { kev_generated_at: string | null; affected_generated_from: string | null },
): Report {
  const { assets, issues } = readInventory(text);
  const index = new Map(affected.map((r) => [r.cve, r]));
  let findings: Finding[] = [];
  for (const a of assets) findings = findings.concat(matchAsset(a, kev, index));
  findings = sortFindings(findings);
  const count = (s: Status) => findings.filter((f) => f.status === s).length;
  return {
    report: 'india-threat-tracker-exposure',
    matcher_version: MATCHER_VERSION,
    data: meta,
    scope: SCOPE_NOTE,
    summary: {
      assets: assets.length,
      assets_with_findings: new Set(findings.map((f) => f.asset_row)).size,
      affected: count('affected'),
      candidate: count('candidate'),
      insufficient: count('insufficient'),
      'no-match': assets.length - new Set(findings.map((f) => f.asset_row)).size,
    },
    issues,
    findings,
  };
}

// ── Exports ────────────────────────────────────────────────────────────────
/** Neutralise spreadsheet formulas: a cell starting with = + - @ tab or CR gets a leading apostrophe. */
export function safeCell(v: string): string {
  return /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
}

function csvField(v: string): string {
  const s = safeCell(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const EXPORT_COLUMNS = [
  'tier', 'status', 'asset_id', 'asset_row', 'vendor', 'product', 'version', 'cve', 'record_product', 'identity',
  'evidence', 'affected_ranges', 'kev_date_added', 'kev_due_date', 'known_ransomware', 'epss', 'epss_date',
  'internet_exposed', 'criticality', 'environment', 'why', 'required_action',
] as const;

export function toCsv(findings: Finding[]): string {
  const lines = [EXPORT_COLUMNS.join(',')];
  for (const f of findings) {
    const values: Record<string, string> = {
      ...Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v == null ? '' : String(v)])),
      evidence: f.evidence.join(' | '),
      affected_ranges: f.affected_ranges.join(' | '),
      known_ransomware: f.known_ransomware ? 'yes' : 'no',
      epss: f.epss == null ? '' : f.epss.toFixed(5),
    };
    lines.push(EXPORT_COLUMNS.map((c) => csvField(values[c] ?? '')).join(','));
  }
  return lines.join('\n') + '\n';
}

export function toJson(report: Report, findings: Finding[] = report.findings): string {
  return JSON.stringify({ ...report, findings }, null, 2) + '\n';
}
