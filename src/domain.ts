// Turning whatever the caller had in their spreadsheet into a domain worth querying. Shares its
// shape with the Website Contact Finder and Tech Stack Detector so all three read a column the same
// way. Pure and unit tested.

/** Second-level suffixes that are really part of the public suffix, e.g. `co` in `co.uk`. */
const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'ltd', 'plc', 'sch', 'nhs', 'mod', 'me']);

/**
 * The registrable domain, e.g. `rpearson.co.uk` from `https://www.mail.rpearson.co.uk/contact`.
 * This is the name a registry actually holds a record for, so it is what gets queried.
 */
export function registrableDomain(raw: unknown): string | null {
    if (raw === null || raw === undefined) return null;
    let value = String(raw).trim().toLowerCase();
    if (value === '') return null;
    value = value.replace(/^mailto:/i, '').replace(/\s+/g, '');
    // An email address in a domain column still names the domain.
    if (/^[^@/]+@[^@/]+\.[a-z]{2,}$/i.test(value)) value = value.split('@')[1];
    if (value.includes('://')) {
        try {
            value = new URL(value).hostname;
        } catch {
            return null;
        }
    }
    const host = value
        .replace(/^www\./, '')
        .replace(/\.$/, '')
        .split('/')[0]
        .split('?')[0]
        .split('#')[0]
        .split(':')[0];
    if (!host.includes('.')) return null;
    // Only letters, digits, hyphens and dots. Anything else is a stray spreadsheet value, and an
    // internationalised name arrives as punycode from the URL parser above.
    if (!/^[a-z0-9.-]+$/.test(host)) return null;
    const labels = host.split('.');
    if (labels.some((l) => l === '' || l.length > 63)) return null;
    const tld = labels[labels.length - 1];
    // A bare number ('1') or a price ('9.99') both reach here from an unrelated column.
    if (!/^[a-z]{2,}$/.test(tld)) return null;
    if (labels.length <= 2) return labels.join('.');
    const secondLast = labels[labels.length - 2];
    return labels.slice(SECOND_LEVEL.has(secondLast) ? -3 : -2).join('.');
}

export function tldOf(domain: string): string {
    return domain.split('.').pop() ?? '';
}

/** Guesses which column holds the domain, so most people never set the field by hand. */
export function detectDomainField(rows: Record<string, unknown>[], sample = 50): string | null {
    if (rows.length === 0) return null;
    const preferred = ['domain', 'domainname', 'domain_name', 'website', 'websiteurl', 'website_url', 'url', 'site', 'siteurl', 'homepage', 'web', 'weburl', 'link', 'companywebsite', 'companydomain', 'hostname'];
    const normalize = (s: string) => s.toLowerCase().replace(/[\s_-]/g, '');
    const keys = new Set<string>();
    for (const row of rows.slice(0, sample)) for (const k of Object.keys(row)) keys.add(k);
    for (const want of preferred) {
        for (const key of keys) if (normalize(key) === normalize(want)) return key;
    }
    const window = rows.slice(0, sample);
    let best: string | null = null;
    let bestHits = 0;
    for (const key of keys) {
        let hits = 0;
        for (const row of window) {
            const v = row[key];
            if ((typeof v === 'string' || typeof v === 'number') && registrableDomain(v) !== null) hits += 1;
        }
        if (hits > bestHits) {
            bestHits = hits;
            best = key;
        }
    }
    return bestHits >= Math.max(1, window.length * 0.5) ? best : null;
}

/**
 * Calendar days from `then` to `now` in UTC, negative when `then` is in the future.
 *
 * Deliberately measured between UTC dates rather than between instants. Registry dates carry a time
 * of day (an expiry of 2026-10-01T18:19:52Z), and subtracting instants makes "expires on the 1st,
 * and today is the 11th" come out as 19 days rather than the 20 anyone reading the two dates would
 * count. Doing it on instants and negating the result was also off by one in the unsafe direction
 * for an expiry warning: it reported more days remaining than there were.
 */
export function daysBetween(then: Date, now: Date): number {
    const utcDay = (d: Date) => Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
    return Math.round((utcDay(now) - utcDay(then)) / 86_400_000);
}

export interface DerivedDates {
    domainAgeDays: number | null;
    domainAgeYears: number | null;
    daysUntilExpiry: number | null;
    isExpired: boolean | null;
    expiringSoon: boolean | null;
    isNewDomain: boolean | null;
}

/**
 * The numbers people actually filter on. Every one is null when the registry did not publish the
 * date it needs, rather than 0, because a confident wrong number is worse than a blank.
 */
export function deriveDates(registeredOn: string | null, expiresOn: string | null, now: Date, expiringWithinDays: number, newerThanDays: number): DerivedDates {
    const reg = registeredOn ? new Date(registeredOn) : null;
    const exp = expiresOn ? new Date(expiresOn) : null;
    const regValid = reg && !Number.isNaN(reg.getTime()) ? reg : null;
    const expValid = exp && !Number.isNaN(exp.getTime()) ? exp : null;
    const ageDays = regValid ? daysBetween(regValid, now) : null;
    const untilExpiry = expValid ? daysBetween(now, expValid) : null;
    return {
        domainAgeDays: ageDays,
        domainAgeYears: ageDays === null ? null : Math.round((ageDays / 365.25) * 10) / 10,
        daysUntilExpiry: untilExpiry,
        isExpired: untilExpiry === null ? null : untilExpiry < 0,
        expiringSoon: untilExpiry === null ? null : untilExpiry >= 0 && untilExpiry <= expiringWithinDays,
        isNewDomain: ageDays === null ? null : ageDays <= newerThanDays,
    };
}

/** A domain is "locked" when the registry or registrar has set any transfer-prohibited status. */
export function isLocked(statuses: string[]): boolean {
    return statuses.some((s) => /transfer prohibited/i.test(s));
}

export function isPendingDelete(statuses: string[]): boolean {
    return statuses.some((s) => /pending\s*delete|redemption/i.test(s));
}
