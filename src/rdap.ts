// RDAP is the registries' own replacement for WHOIS: a documented JSON protocol (RFC 9082/9083)
// served by the registry that actually holds the record, with no key, no scraping and no third-party
// middleman. IANA publishes the TLD-to-server map at https://data.iana.org/rdap/dns.json.
//
// Confirmed live on 11 Sept 2026: the bootstrap file lists servers for ~1,200 TLDs, and a plain GET
// returns registration date, expiry, registrar, nameservers and status. Some ccTLDs (.ie, .de, .so,
// .sh among them) run no RDAP server at all, which is reported honestly as `no_rdap_server` and
// never charged, rather than guessed at from some other source.
import type { LookupResult, RdapRecord } from './types.js';

export const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
export const USER_AGENT = 'domain-expiry-check/1.0 (+https://github.com/Nero-Engine/domain-expiry-check)';

export type FetchLike = (url: string, init: { signal: AbortSignal; headers: Record<string, string>; redirect: 'follow' }) => Promise<Response>;

export interface BootstrapFile {
    services: [string[], string[]][];
    publication?: string;
    version?: string;
}

/** TLD (no dot, lower case) to the RDAP base URLs that serve it, in the order IANA lists them. */
export type ServerMap = Map<string, string[]>;

export function parseBootstrap(file: BootstrapFile): ServerMap {
    const map: ServerMap = new Map();
    for (const [tlds, urls] of file.services ?? []) {
        const bases = (urls ?? []).filter((u) => typeof u === 'string' && /^https?:\/\//i.test(u)).map((u) => u.replace(/\/+$/, ''));
        if (bases.length === 0) continue;
        for (const tld of tlds ?? []) {
            const key = String(tld).toLowerCase().replace(/^\./, '');
            if (key) map.set(key, bases);
        }
    }
    return map;
}

/** Pulls one field out of a jCard (RFC 7095), the shape RDAP wraps contact details in. */
export function vcardField(entity: unknown, field: string): string | null {
    const vcard = (entity as { vcardArray?: unknown[] } | null)?.vcardArray;
    if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return null;
    for (const item of vcard[1] as unknown[]) {
        if (!Array.isArray(item) || item[0] !== field) continue;
        const value = item[3];
        if (typeof value === 'string' && value.trim() !== '') return value.trim();
        // 'adr' arrives as a 7-slot array: PO box, extended, street, locality, region, post code, country.
        if (Array.isArray(value)) {
            const joined = value.filter((v) => typeof v === 'string' && v.trim() !== '');
            if (field === 'adr') return (value[6] as string | undefined)?.trim() || null;
            if (joined.length > 0) return String(joined[joined.length - 1]).trim();
        }
    }
    return null;
}

function entitiesWithRole(json: Record<string, unknown>, role: string): Record<string, unknown>[] {
    const out: Record<string, unknown>[] = [];
    const walk = (list: unknown, depth: number) => {
        if (!Array.isArray(list) || depth > 3) return;
        for (const raw of list) {
            if (raw === null || typeof raw !== 'object') continue;
            const entity = raw as Record<string, unknown>;
            const roles = Array.isArray(entity.roles) ? entity.roles.map((r) => String(r).toLowerCase()) : [];
            if (roles.includes(role)) out.push(entity);
            walk(entity.entities, depth + 1);
        }
    };
    walk(json.entities, 0);
    return out;
}

function eventDate(json: Record<string, unknown>, action: string): string | null {
    const events = Array.isArray(json.events) ? json.events : [];
    for (const raw of events) {
        if (raw === null || typeof raw !== 'object') continue;
        const event = raw as Record<string, unknown>;
        if (String(event.eventAction ?? '').toLowerCase() !== action) continue;
        const date = String(event.eventDate ?? '');
        const parsed = new Date(date);
        if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
    }
    return null;
}

/**
 * Reads an RDAP domain object into flat fields. Anything the registry did not publish comes back
 * null; nothing is inferred. Registrant details are deliberately limited to organisation and
 * country, so a person's name, email, phone or street address is never returned by this Actor.
 */
export function parseRdap(json: Record<string, unknown>): RdapRecord {
    const registrar = entitiesWithRole(json, 'registrar')[0] ?? null;
    const registrant = entitiesWithRole(json, 'registrant')[0] ?? null;

    let registrarIanaId: string | null = null;
    const publicIds = (registrar as { publicIds?: unknown[] } | null)?.publicIds;
    if (Array.isArray(publicIds)) {
        for (const raw of publicIds) {
            if (raw === null || typeof raw !== 'object') continue;
            const id = raw as Record<string, unknown>;
            if (/iana/i.test(String(id.type ?? ''))) registrarIanaId = String(id.identifier ?? '') || null;
        }
    }

    const nameservers = (Array.isArray(json.nameservers) ? json.nameservers : [])
        .map((raw) => (raw !== null && typeof raw === 'object' ? String((raw as Record<string, unknown>).ldhName ?? '') : ''))
        .filter((n) => n !== '')
        .map((n) => n.toLowerCase().replace(/\.$/, ''));

    const statuses = (Array.isArray(json.status) ? json.status : []).map((s) => String(s)).filter((s) => s !== '');

    const secureDns = json.secureDNS as { delegationSigned?: unknown } | undefined;
    const dnssec = secureDns && typeof secureDns.delegationSigned === 'boolean' ? secureDns.delegationSigned : null;

    const registrantOrganization = registrant ? vcardField(registrant, 'org') : null;
    const registrantCountry = registrant ? vcardField(registrant, 'adr') : null;

    return {
        ldhName: typeof json.ldhName === 'string' ? json.ldhName.toLowerCase() : null,
        registeredOn: eventDate(json, 'registration'),
        expiresOn: eventDate(json, 'expiration'),
        lastChangedOn: eventDate(json, 'last changed'),
        registrar: registrar ? vcardField(registrar, 'fn') : null,
        registrarIanaId,
        nameservers: [...new Set(nameservers)],
        statuses,
        dnssec,
        registrantOrganization,
        registrantCountry: registrantCountry && /^[A-Za-z]{2,3}$/.test(registrantCountry) ? registrantCountry.toUpperCase() : registrantCountry,
        contactDataRedacted: registrantOrganization === null,
    };
}

/** Serialises requests per RDAP host and leaves a gap between them, because registries rate-limit. */
export class HostThrottle {
    private readonly nextFreeAt = new Map<string, number>();

    constructor(private readonly gapMs: number) {}

    async take(host: string): Promise<void> {
        const now = Date.now();
        const earliest = this.nextFreeAt.get(host) ?? 0;
        const waitMs = Math.max(0, earliest - now);
        this.nextFreeAt.set(host, Math.max(now, earliest) + this.gapMs);
        if (waitMs > 0) {
            await new Promise((resolve) => {
                setTimeout(resolve, waitMs);
            });
        }
    }
}

export interface LookupOptions {
    servers: ServerMap;
    fetchImpl: FetchLike;
    timeoutMs: number;
    throttle: HostThrottle;
    /** Retries per server on a 429 or 5xx. */
    maxRetries?: number;
    sleep?: (ms: number) => Promise<void>;
}

async function defaultSleep(ms: number): Promise<void> {
    await new Promise<void>((resolve) => {
        setTimeout(resolve, ms);
    });
}

function hostOf(url: string): string {
    try {
        return new URL(url).host;
    } catch {
        return url;
    }
}

// Nominet's RDAP terms (https://registrars.nominet.uk/rdap/tos/, read 30 Sept 2026) forbid "any
// copying or transmission of data for commercial purposes" and "high volume, automated, electronic
// processes" against its server. That server answers for .uk and every TLD Nominet runs the back end
// for (.cymru, .wales, .jobs, .bbc, .amazon and about 80 more in IANA's file), so this paid Actor
// never sends it a request. Blocked by server host, so a TLD moving to or from Nominet is followed
// automatically, plus the .uk family by name in case the bootstrap ever omits it.
export const BLOCKED_RDAP_HOST_SUFFIXES = ['nominet.uk'];
export const BLOCKED_TLDS = new Set(['uk', 'cymru', 'wales']);

function hostIsBlocked(base: string): boolean {
    let host: string;
    try {
        host = new URL(base).hostname.toLowerCase();
    } catch {
        return false;
    }
    return BLOCKED_RDAP_HOST_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

/** True when this TLD must not be queried because its RDAP server's terms forbid commercial automated lookups. */
export function isBlockedByRegistryTerms(tld: string, servers: ServerMap): boolean {
    if (BLOCKED_TLDS.has(tld)) return true;
    return (servers.get(tld) ?? []).some(hostIsBlocked);
}

export function registryTermsDetail(tld: string): string {
    if (tld === 'uk') return 'Not checked: the .uk registry (Nominet) does not permit commercial automated lookups. Not charged.';
    return `Not checked: the .${tld} registry's RDAP server is run by Nominet, whose terms do not permit commercial automated lookups. Not charged.`;
}

/**
 * Asks the registry about one domain. Only a real record (`ok`) or a registry saying the name is not
 * registered (`not_registered`) count as answers; a missing server, a refusal, a rate limit or a
 * network failure are reported as themselves so the caller is never charged for a non-answer.
 */
export async function lookupDomain(domain: string, tld: string, options: LookupOptions): Promise<LookupResult> {
    if (isBlockedByRegistryTerms(tld, options.servers)) {
        return { status: 'not_checked_registry_terms', statusDetail: registryTermsDetail(tld), record: null, rdapServer: null, attempts: 0 };
    }
    const bases = options.servers.get(tld);
    if (!bases || bases.length === 0) {
        return {
            status: 'no_rdap_server',
            statusDetail: `The .${tld} registry does not publish an RDAP server, so no authoritative record could be read. Not charged.`,
            record: null,
            rdapServer: null,
            attempts: 0,
        };
    }

    const maxRetries = options.maxRetries ?? 2;
    const sleep = options.sleep ?? defaultSleep;
    let attempts = 0;
    let lastDetail = 'The registry did not answer.';
    let lastStatus: LookupResult['status'] = 'unreachable';

    for (const base of bases) {
        const url = `${base}/domain/${encodeURIComponent(domain)}`;
        for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
            await options.throttle.take(hostOf(base));
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), options.timeoutMs);
            attempts += 1;
            try {
                const response = await options.fetchImpl(url, {
                    signal: controller.signal,
                    redirect: 'follow',
                    headers: { accept: 'application/rdap+json, application/json', 'user-agent': USER_AGENT },
                });
                if (response.status === 200) {
                    const json = (await response.json()) as Record<string, unknown>;
                    return { status: 'ok', statusDetail: null, record: parseRdap(json), rdapServer: base, attempts };
                }
                if (response.status === 404) {
                    return {
                        status: 'not_registered',
                        statusDetail: 'The registry has no record for this domain, so it is not currently registered.',
                        record: null,
                        rdapServer: base,
                        attempts,
                    };
                }
                if (response.status === 429) {
                    lastStatus = 'rate_limited';
                    lastDetail = `The .${tld} registry is rate-limiting this run (HTTP 429). Not charged. Lower 'Concurrency' or split the list across runs.`;
                    const retryAfter = Number(response.headers.get('retry-after') ?? '0');
                    const backoffMs = retryAfter > 0 ? Math.min(retryAfter * 1000, 30_000) : 1000 * 2 ** attempt;
                    if (attempt < maxRetries) {
                        await sleep(backoffMs);
                        continue;
                    }
                    break;
                }
                if (response.status === 403 || response.status === 401) {
                    lastStatus = 'refused';
                    lastDetail = `The .${tld} registry refused the request (HTTP ${response.status}). Some registries only answer RDAP for approved clients. Not charged.`;
                    break;
                }
                if (response.status >= 500) {
                    lastStatus = 'server_error';
                    lastDetail = `The .${tld} registry's RDAP server returned HTTP ${response.status}. Not charged.`;
                    if (attempt < maxRetries) {
                        await sleep(500 * 2 ** attempt);
                        continue;
                    }
                    break;
                }
                lastStatus = 'server_error';
                lastDetail = `The registry responded with HTTP ${response.status}. Not charged.`;
                break;
            } catch (e) {
                lastStatus = 'unreachable';
                const message = (e as Error).name === 'AbortError' ? `timed out after ${Math.round(options.timeoutMs / 1000)}s` : (e as Error).message;
                lastDetail = `Could not reach the .${tld} registry's RDAP server (${message}). Not charged.`;
                if (attempt < maxRetries) {
                    await sleep(500 * 2 ** attempt);
                    continue;
                }
            } finally {
                clearTimeout(timer);
            }
            break;
        }
    }

    return { status: lastStatus, statusDetail: lastDetail, record: null, rdapServer: null, attempts };
}

/** Downloads and parses IANA's bootstrap file. Without it nothing can be looked up, so this throws. */
export async function loadServers(fetchImpl: FetchLike, timeoutMs: number): Promise<{ servers: ServerMap; publication: string | null }> {
    let lastError = '';
    for (let attempt = 0; attempt < 3; attempt += 1) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            const response = await fetchImpl(BOOTSTRAP_URL, {
                signal: controller.signal,
                redirect: 'follow',
                headers: { accept: 'application/json', 'user-agent': USER_AGENT },
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const file = (await response.json()) as BootstrapFile;
            const servers = parseBootstrap(file);
            if (servers.size === 0) throw new Error('the file listed no RDAP servers');
            return { servers, publication: file.publication ?? null };
        } catch (e) {
            lastError = (e as Error).message;
            await defaultSleep(500 * 2 ** attempt);
        } finally {
            clearTimeout(timer);
        }
    }
    throw new Error(`Could not download IANA's RDAP server list from ${BOOTSTRAP_URL} (${lastError}). This run cannot look up any domain without it; try again shortly.`);
}
