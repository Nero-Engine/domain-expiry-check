// Shared types for the domain WHOIS/RDAP checker.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Item = Record<string, any>;

export type FileFormat = 'auto' | 'csv' | 'tsv' | 'json' | 'jsonl' | 'xlsx';

/**
 * The outcome of one domain. Only `ok` and `not_registered` are authoritative answers, and they are
 * the only two that are ever charged: everything else means the registry did not tell us anything.
 */
export type DomainStatus =
    | 'ok'
    | 'not_registered'
    | 'no_rdap_server'
    /** No RDAP server for the ending, but public DNS shows the domain in use, so it is registered (no dates). */
    | 'registered_dns'
    /** No RDAP server for the ending, and the ending's DNS says the name does not exist: almost certainly available. */
    | 'not_in_dns'
    /** The TLD's RDAP server (Nominet, for .uk and others) forbids commercial automated lookups, so no request is sent. */
    | 'not_checked_registry_terms'
    | 'rate_limited'
    | 'refused'
    | 'server_error'
    | 'unreachable'
    | 'invalid_domain'
    | 'skipped_budget';

export interface RdapRecord {
    /** The domain exactly as the registry echoed it back, when it did. */
    ldhName: string | null;
    registeredOn: string | null;
    expiresOn: string | null;
    lastChangedOn: string | null;
    registrar: string | null;
    registrarIanaId: string | null;
    nameservers: string[];
    statuses: string[];
    dnssec: boolean | null;
    registrantOrganization: string | null;
    registrantCountry: string | null;
    /** True when the registry publishes no registrant organisation at all, the norm since GDPR. */
    contactDataRedacted: boolean;
}

export interface LookupResult {
    status: DomainStatus;
    statusDetail: string | null;
    record: RdapRecord | null;
    rdapServer: string | null;
    /** How many HTTP requests this domain actually cost us, for the run log only. */
    attempts: number;
}

export interface ActorInput {
    domains?: string[];
    names?: string[];
    tlds?: string[];
    datasetId?: string;
    fileUrl?: string;
    fileFormat?: FileFormat;
    data?: Item[];
    domainField?: string;

    dnsFallback?: boolean;
    keep?: 'all' | 'registered' | 'unregistered' | 'expiring' | 'new' | 'problems';
    expiringWithinDays?: number;
    newerThanDays?: number;
    includeRegistrantOrganization?: boolean;

    concurrency?: number;
    requestTimeoutSecs?: number;

    maxItems?: number;
    exportFormats?: string[];
    outputDatasetName?: string;
    webhookUrl?: string;
}

export interface DomainSummary {
    source: 'dataset' | 'fileUrl' | 'inline' | 'domains' | 'names';
    sourceFormat?: string;
    domainField: string;
    inputRecordCount: number;
    domainsChecked: number;
    /** Authoritative answers, i.e. the number of charged events. */
    domainsAnswered: number;
    registeredCount: number;
    unregisteredCount: number;
    outputRecordCount: number;
    statusCounts: Record<string, number>;
    topRegistrars: { name: string; domains: number }[];
    expiringSoonCount: number;
    newDomainCount: number;
    oldestDomain: { domain: string; registeredOn: string } | null;
    newestDomain: { domain: string; registeredOn: string } | null;
    unsupportedTlds: string[];
    /** TLDs skipped without a request because their RDAP server's terms forbid commercial lookups (Nominet). */
    registryTermsBlockedTlds?: string[];
    dataNote: string;
    exportUrls: Record<string, string>;
    durationMs: number;
    warnings: string[];
    webhookDelivered?: boolean;
}
