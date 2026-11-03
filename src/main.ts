// Domain Expiry Check, a GitHub Action (and a plain Node CLI).
// For a list of domains or host names it reads (1) the domain's registration expiry from the
// registry's own RDAP server (the official replacement for WHOIS, found through IANA's list) and
// (2) the expiry and trust of the TLS certificate the host serves. It writes a job summary table,
// step outputs and annotations, and fails the step when anything expires within the chosen number of
// days, a certificate is not trusted, or a domain is on hold, in redemption or no longer registered.
// Run it on a weekly schedule: GitHub emails the repo owner when a scheduled run fails, so it works as
// a free expiry alert with no server. Node's built-in fetch and tls only, no dependencies.

import { appendFileSync, readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

import { HostThrottle, loadServers, lookupDomain, type FetchLike, type ServerMap } from './rdap.js';
import { registrableDomain, tldOf } from './domain.js';
import { checkSsl, explainTrustError, type SslResult } from './ssl.js';
import type { LookupResult } from './types.js';

const VERSION = '1.0.0';
const ACTOR_URL = 'https://apify.com/nerolabs/domain-whois-checker';
const REPO_URL = 'https://github.com/Nero-Engine/domain-expiry-check';
const HARD_MAX = 200;
const DAY_MS = 86_400_000;

/** Shared platform hosts: the registrable domain belongs to the platform, which renews it, so only TLS is checked. */
export const PLATFORM_SUFFIXES = ['github.io', 'workers.dev', 'pages.dev', 'vercel.app', 'netlify.app', 'herokuapp.com', 'web.app', 'firebaseapp.com', 'azurewebsites.net', 'cloudfront.net', 'onrender.com', 'fly.dev', 'railway.app', 'blogspot.com', 'wordpress.com', 'myshopify.com', 'wixsite.com', 'squarespace.com', 'webflow.io', 'framer.app', 'appspot.com', 'amplifyapp.com', 'surge.sh', 'gitlab.io', 'replit.app', 'deno.dev', 'supabase.co'];

export function platformOf(host: string): string | null {
    return PLATFORM_SUFFIXES.find((s) => host === s || host.endsWith(`.${s}`)) ?? null;
}

type Check = 'domain' | 'ssl';

interface Options {
    hosts: string[];
    file: string | null;
    checks: Check[];
    failDays: number;
    warnDays: number;
    sslFailDays: number;
    failOnProblems: boolean;
    sslPort: number;
    timeoutMs: number;
}

export interface Row {
    host: string;
    domain: string | null;
    domainStatus: string;
    domainDetail: string | null;
    domainExpiresOn: string | null;
    domainDaysLeft: number | null;
    registrar: string | null;
    registryStatuses: string[];
    sslStatus: string;
    sslDetail: string | null;
    sslExpiresOn: string | null;
    sslDaysLeft: number | null;
    sslIssuer: string | null;
    sslTrusted: boolean | null;
    failing: string[];
    warnings: string[];
}

const inActions = process.env.GITHUB_ACTIONS === 'true';

function input(name: string, fallback = ''): string {
    const v = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`];
    return v === undefined || v.trim() === '' ? fallback : v.trim();
}

/** Splits a list on new lines, commas and spaces, dropping # comments. */
export function splitList(v: string): string[] {
    return v.split(/\r?\n/).map((line) => line.replace(/#.*$/, '')).join(' ').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
}

function clampInt(v: string, def: number, min: number, max: number): number {
    const n = Math.round(Number(v));
    return Number.isFinite(n) && v !== '' ? Math.min(Math.max(n, min), max) : def;
}

export function parseChecks(v: string): Check[] {
    const s = v.toLowerCase();
    if (s === 'domain' || s === 'registration') return ['domain'];
    if (s === 'ssl' || s === 'tls' || s === 'certificate') return ['ssl'];
    return ['domain', 'ssl'];
}

/** The host name to test from a domain, host or full URL; null when it is not one. */
export function hostOf(raw: string): string | null {
    let s = raw.trim().toLowerCase();
    if (!s) return null;
    if (/^[^@/]+@[^@/]+\.[a-z]{2,}$/i.test(s)) s = s.split('@')[1];
    try {
        const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
        const h = u.hostname.replace(/\.$/, '');
        if (!h.includes('.') || !/^[a-z0-9.-]+$/.test(h) || /^\d+(\.\d+){3}$/.test(h)) return null;
        if (!/^[a-z]{2,}$/.test(h.split('.').pop() ?? '')) return null;
        return h;
    } catch {
        return null;
    }
}

function readOptions(): Options {
    if (inActions) {
        return {
            hosts: splitList(input('domains')),
            file: input('domains-file') || null,
            checks: parseChecks(input('check', 'both')),
            failDays: clampInt(input('fail-within-days'), 30, 0, 3650),
            warnDays: clampInt(input('warn-within-days'), 60, 0, 3650),
            sslFailDays: clampInt(input('ssl-fail-within-days'), 14, 0, 3650),
            failOnProblems: !/^(false|no|0|off)$/i.test(input('fail-on-problems', 'true')),
            sslPort: clampInt(input('ssl-port'), 443, 1, 65535),
            timeoutMs: clampInt(input('timeout-seconds'), 20, 5, 120) * 1000,
        };
    }
    // CLI: node dist/index.js <domain> [domain...] [--file list.txt] [--check both|domain|ssl]
    //      [--fail-within-days 30] [--ssl-fail-within-days 14] [--warn-within-days 60] [--no-fail-on-problems] [--port 443]
    const args = process.argv.slice(2);
    const o: Options = { hosts: [], file: null, checks: ['domain', 'ssl'], failDays: 30, warnDays: 60, sslFailDays: 14, failOnProblems: true, sslPort: 443, timeoutMs: 20_000 };
    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === '--file') o.file = args[++i] ?? null;
        else if (a === '--check') o.checks = parseChecks(args[++i] ?? 'both');
        else if (a === '--fail-within-days') o.failDays = clampInt(args[++i] ?? '', 30, 0, 3650);
        else if (a === '--warn-within-days') o.warnDays = clampInt(args[++i] ?? '', 60, 0, 3650);
        else if (a === '--ssl-fail-within-days') o.sslFailDays = clampInt(args[++i] ?? '', 14, 0, 3650);
        else if (a === '--no-fail-on-problems') o.failOnProblems = false;
        else if (a === '--port') o.sslPort = clampInt(args[++i] ?? '', 443, 1, 65535);
        else if (a === '--help' || a === '-h') {
            console.log('Usage: node dist/index.js <domain> [domain...] [--file domains.txt] [--check both|domain|ssl] [--fail-within-days 30] [--ssl-fail-within-days 14] [--warn-within-days 60] [--no-fail-on-problems] [--port 443]');
            process.exit(0);
        } else o.hosts.push(...splitList(a));
    }
    return o;
}

// ----- GitHub workflow commands -----
function escapeData(s: string): string {
    return s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}
function warn(msg: string): void {
    console.log(inActions ? `::warning::${escapeData(msg)}` : `WARNING: ${msg}`);
}
function annotate(level: 'error' | 'warning' | 'notice', title: string, msg: string): void {
    if (inActions) console.log(`::${level} title=${escapeData(title).replace(/:/g, '%3A').replace(/,/g, '%2C')}::${escapeData(msg)}`);
}
function setOutput(name: string, value: string): void {
    const file = process.env.GITHUB_OUTPUT;
    if (!file) return;
    const delim = `EOF_${randomBytes(8).toString('hex')}`;
    appendFileSync(file, `${name}<<${delim}\n${value}\n${delim}\n`);
}
function summary(md: string): void {
    const file = process.env.GITHUB_STEP_SUMMARY;
    if (file) appendFileSync(file, md);
}
function fatal(msg: string): void {
    if (inActions) console.log(`::error::${escapeData(msg)}`); else console.error(msg);
    setOutput('result', 'error');
    summary(`## Domain Expiry Check\n\n**Not run:** ${msg}\n`);
    process.exitCode = 1;
}

// ----- judging -----
export function daysLeft(iso: string | null, now: number): number | null {
    if (!iso) return null;
    const t = new Date(iso).getTime();
    return Number.isNaN(t) ? null : Math.floor((t - now) / DAY_MS);
}

/** Registry statuses that mean the domain is about to stop working or be lost. */
export function dangerStatuses(statuses: string[]): string[] {
    return statuses.filter((s) => /hold|redemption|pending ?delete|pending ?restore|inactive/i.test(s));
}

export function judge(row: Row, o: Pick<Options, 'failDays' | 'warnDays' | 'sslFailDays' | 'failOnProblems'>): void {
    const fail: string[] = [];
    const soft: string[] = [];
    const when = (d: number) => (d < 0 ? `expired ${-d} day(s) ago` : d === 0 ? 'expires today' : `expires in ${d} day(s)`);
    if (row.domainDaysLeft !== null) {
        if (row.domainDaysLeft <= o.failDays) fail.push(`Domain registration ${when(row.domainDaysLeft)} (${row.domainExpiresOn?.slice(0, 10)})${row.registrar ? `, registrar ${row.registrar}` : ''}`);
        else if (row.domainDaysLeft <= o.warnDays) soft.push(`Domain registration ${when(row.domainDaysLeft)}`);
    }
    if (row.sslDaysLeft !== null) {
        // Certificates get their own, shorter window: Let's Encrypt and most automated certificates renew themselves at 30 days left.
        if (row.sslDaysLeft <= o.sslFailDays) fail.push(`TLS certificate ${when(row.sslDaysLeft)} (${row.sslExpiresOn?.slice(0, 10)})${row.sslIssuer ? `, issuer ${row.sslIssuer}` : ''}`);
        else if (row.sslDaysLeft <= o.sslFailDays + 7) soft.push(`TLS certificate ${when(row.sslDaysLeft)}`);
    }
    const problems: string[] = [];
    if (row.sslTrusted === false && !(row.sslDaysLeft !== null && row.sslDaysLeft < 0)) problems.push(`TLS ${row.sslDetail ?? 'certificate not trusted'}`);
    const danger = dangerStatuses(row.registryStatuses);
    if (danger.length) problems.push(`Registry status: ${danger.join(', ')}`);
    if (row.domainStatus === 'not_registered') problems.push('Domain is not registered (lapsed or never bought)');
    if (o.failOnProblems) fail.push(...problems); else soft.push(...problems);
    if (row.sslStatus === 'unreachable') soft.push(`TLS not checked: ${row.sslDetail}`);
    if (row.domainStatus !== 'ok' && row.domainStatus !== 'not_registered' && row.domainStatus !== 'skipped' && row.domainStatus !== 'platform') soft.push(`Registration date not read: ${row.domainDetail}`);
    row.failing = fail;
    row.warnings = soft;
}

// ----- output -----
const dayCell = (d: number | null) => (d === null ? '' : `${d <= 14 ? '🔴' : d <= 30 ? '🟠' : d <= 60 ? '🟡' : '🟢'} ${d}`);
const pipe = (s: string) => s.replace(/\|/g, '/');

function domainCell(r: Row): string {
    if (r.domainStatus === 'skipped') return '';
    if (r.domainStatus === 'ok') return `${r.domainExpiresOn?.slice(0, 10) ?? 'no date published'}`;
    if (r.domainStatus === 'not_registered') return '❌ not registered';
    if (r.domainStatus === 'platform') return '➖ platform domain';
    return `➖ ${r.domainStatus === 'no_rdap_server' ? 'registry has no RDAP' : r.domainStatus === 'not_checked_registry_terms' ? 'not checked (registry terms)' : r.domainStatus}`;
}

function markdown(rows: Row[], o: Options, failed: boolean): string {
    const lines = ['## Domain Expiry Check', ''];
    const checks = o.checks.map((c) => (c === 'domain' ? 'domain registration' : 'TLS certificate')).join(' + ');
    lines.push(`**Result: ${failed ? 'failing' : 'passing'}** · checks: ${checks} · fails when a domain expires within **${o.failDays} days** or a certificate within **${o.sslFailDays} days**${o.failOnProblems ? ', a certificate is not trusted, or a domain is on hold, in redemption or not registered' : ''} · ${rows.length} host(s)`, '');
    lines.push('| Host | Domain expires | Days left | Registrar | TLS expires | Days left | Issuer | Notes |', '|---|---|---|---|---|---|---|---|');
    const sorted = [...rows].sort((a, b) => (b.failing.length - a.failing.length) || (Math.min(a.domainDaysLeft ?? 1e9, a.sslDaysLeft ?? 1e9) - Math.min(b.domainDaysLeft ?? 1e9, b.sslDaysLeft ?? 1e9)));
    for (const r of sorted) {
        const tls = r.sslStatus === 'skipped' ? '' : r.sslStatus === 'ok' ? `${r.sslExpiresOn?.slice(0, 10)}${r.sslTrusted === false ? ' ⚠️' : ''}` : '➖ no answer';
        const notes = [...r.failing.map((f) => `❗ ${f}`), ...r.warnings].join('; ');
        lines.push(`| ${r.host}${r.failing.length ? ' ❗' : ''} | ${domainCell(r)} | ${dayCell(r.domainDaysLeft)} | ${pipe(r.registrar ?? '')} | ${tls} | ${dayCell(r.sslDaysLeft)} | ${pipe(r.sslIssuer ?? '')} | ${pipe(notes).slice(0, 300)} |`);
    }
    lines.push('', '<sub>Domain dates come from the registry\'s own RDAP server (the official replacement for WHOIS, listed by IANA), never guessed. Some endings (for example .de, .ie) publish no RDAP server, and .uk is not queried because Nominet\'s terms do not allow automated lookups, so only the certificate is checked for those. Run this on a weekly `schedule`: GitHub emails you when a scheduled run fails.</sub>', '');
    lines.push(`<sub>Hundreds of domains, from a CSV, Google Sheet or spreadsheet, or checking which name ideas are still free? [Domain WHOIS & Age Checker on Apify](${ACTOR_URL}) reads the same registry records in bulk, filters to the ones expiring soon or newly registered and exports CSV or Excel.</sub>`, '');
    return lines.join('\n');
}

// ----- main -----
async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
    const out: R[] = new Array(items.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
        while (next < items.length) {
            const i = next++;
            out[i] = await fn(items[i]);
        }
    }));
    return out;
}

export async function run(o: Options, now = Date.now()): Promise<Row[] | null> {
    const raw = [...o.hosts];
    if (o.file) {
        try {
            raw.push(...splitList(readFileSync(o.file, 'utf8')));
        } catch (e) {
            fatal(`Could not read domains-file ${o.file}: ${(e as Error).message}`);
            return null;
        }
    }
    const hosts: string[] = [];
    const seen = new Set<string>();
    for (const r of raw) {
        const h = hostOf(r);
        if (!h) { warn(`Skipped, not a domain or host name: ${r}`); continue; }
        if (!seen.has(h)) { seen.add(h); hosts.push(h); }
    }
    if (hosts.length === 0) { fatal('No domains to check. Set `domains` (one per line or comma separated) or `domains-file` (a text file in your repo, one per line).'); return null; }
    if (hosts.length > HARD_MAX) warn(`${hosts.length} hosts given; checking the first ${HARD_MAX}. For bigger lists use ${ACTOR_URL}.`);
    const list = hosts.slice(0, HARD_MAX);
    console.log(`Domain Expiry Check v${VERSION}: ${list.length} host(s), checks ${o.checks.join('+')}, fail within ${o.failDays} days (certificates ${o.sslFailDays})`);

    // Registry lookups, one per registrable domain.
    const lookups = new Map<string, LookupResult>();
    if (o.checks.includes('domain')) {
        let servers: ServerMap | null = null;
        try {
            servers = (await loadServers(fetch as unknown as FetchLike, o.timeoutMs)).servers;
        } catch (e) {
            warn((e as Error).message);
        }
        const domains = [...new Set(list.filter((h) => !platformOf(h)).map((h) => registrableDomain(h)).filter((d): d is string => !!d))];
        if (servers) {
            const throttle = new HostThrottle(400);
            const srv = servers;
            await mapLimit(domains, 4, async (d) => {
                lookups.set(d, await lookupDomain(d, tldOf(d), { servers: srv, fetchImpl: fetch as unknown as FetchLike, timeoutMs: o.timeoutMs, throttle }));
            });
        } else {
            for (const d of domains) lookups.set(d, { status: 'unreachable', statusDetail: 'IANA RDAP list could not be downloaded.', record: null, rdapServer: null, attempts: 0 });
        }
    }
    const ssl = new Map<string, SslResult>();
    if (o.checks.includes('ssl')) {
        await mapLimit(list, 8, async (h) => {
            let r = await checkSsl(h, o.sslPort, o.timeoutMs);
            // One retry: a busy server sometimes resets the first handshake.
            if (r.status === 'unreachable') { await new Promise((ok) => setTimeout(ok, 1500)); r = await checkSsl(h, o.sslPort, o.timeoutMs); }
            ssl.set(h, r);
        });
    }

    return list.map((host) => {
        const platform = platformOf(host);
        const domain = platform ? null : registrableDomain(host);
        const lk = domain ? lookups.get(domain) : undefined;
        const s = ssl.get(host);
        const rec = lk?.record ?? null;
        const row: Row = {
            host, domain,
            domainStatus: !o.checks.includes('domain') ? 'skipped' : platform ? 'platform' : (lk?.status ?? 'invalid_domain'),
            domainDetail: platform ? `${platform} is a shared platform domain, renewed by the platform` : lk?.statusDetail?.replace(/ Not charged\.$/, '').replace(/ Lower 'Concurrency'.*$/, '') ?? null,
            domainExpiresOn: rec?.expiresOn ?? null,
            domainDaysLeft: daysLeft(rec?.expiresOn ?? null, now),
            registrar: rec?.registrar ?? null,
            registryStatuses: rec?.statuses ?? [],
            sslStatus: s ? s.status : 'skipped',
            sslDetail: s ? (s.status === 'ok' ? (s.trusted === false ? explainTrustError(s.trustError) : null) : s.detail) : null,
            sslExpiresOn: s?.validTo ?? null,
            sslDaysLeft: daysLeft(s?.validTo ?? null, now),
            sslIssuer: s?.issuer ?? null,
            sslTrusted: s?.trusted ?? null,
            failing: [], warnings: [],
        };
        judge(row, o);
        return row;
    });
}

async function main(): Promise<void> {
    const o = readOptions();
    const rows = await run(o);
    if (!rows) return;
    for (const r of rows) {
        for (const f of r.failing) annotate('error', 'Domain Expiry Check', `${r.host}: ${f}`);
        for (const w of r.warnings) annotate('warning', 'Domain Expiry Check', `${r.host}: ${w}`);
    }
    const failedRows = rows.filter((r) => r.failing.length > 0);
    const checked = rows.filter((r) => r.domainDaysLeft !== null || r.sslDaysLeft !== null || r.domainStatus === 'not_registered');
    const failed = failedRows.length > 0;
    const allDays = rows.flatMap((r) => [r.domainDaysLeft, r.sslDaysLeft]).filter((d): d is number => d !== null);
    const soonest = allDays.length ? Math.min(...allDays) : null;
    const result = failed ? 'fail' : checked.length === 0 ? 'error' : 'pass';

    setOutput('result', result);
    setOutput('failing-count', String(failedRows.length));
    setOutput('failing-hosts', failedRows.map((r) => r.host).join(','));
    setOutput('soonest-days-left', soonest === null ? '' : String(soonest));
    setOutput('report', JSON.stringify(rows));
    summary(markdown(rows, o, failed));

    console.log('');
    for (const r of rows) {
        const d = r.domainStatus === 'skipped' ? '' : `domain ${r.domainDaysLeft === null ? r.domainStatus : `${r.domainDaysLeft}d`}`;
        const t = r.sslStatus === 'skipped' ? '' : `tls ${r.sslDaysLeft === null ? r.sslStatus : `${r.sslDaysLeft}d`}${r.sslTrusted === false ? ' (untrusted)' : ''}`;
        console.log(`${r.failing.length ? '!' : ' '} ${`${d}  ${t}`.trim().padEnd(34)} ${r.host}`);
        for (const f of r.failing) console.log(`      ${f}`);
    }
    console.log(`\n${result.toUpperCase()}: ${failedRows.length} failing of ${rows.length} host(s); soonest expiry in ${soonest ?? 'n/a'} day(s).`);
    console.log(`Bulk lists, CSV or Sheet input and name-idea checks: ${ACTOR_URL}  (${REPO_URL})`);
    if (result !== 'pass') process.exitCode = 1;
}

if (process.env.DOMAIN_EXPIRY_NO_MAIN !== '1') {
    main().catch((err) => fatal(`Domain Expiry Check crashed: ${(err as Error).message}`));
}
