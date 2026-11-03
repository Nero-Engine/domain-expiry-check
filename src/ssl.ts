// Reads the TLS certificate a host serves, with Node's built-in tls module (no dependencies).
// Reports the expiry date, days left, issuer, and whether the certificate is trusted for that host
// (a wrong-host or self-signed certificate is a problem even when it has not expired).

import tls from 'node:tls';

export interface SslResult {
    status: 'ok' | 'unreachable';
    detail: string | null;
    validTo: string | null;
    validFrom: string | null;
    issuer: string | null;
    /** False when the certificate is not trusted for this host (expired, self-signed, wrong name). */
    trusted: boolean | null;
    trustError: string | null;
    names: string[];
}

export function checkSsl(host: string, port: number, timeoutMs: number): Promise<SslResult> {
    return new Promise((resolve) => {
        let done = false;
        const finish = (r: SslResult) => {
            if (done) return;
            done = true;
            try { socket.destroy(); } catch { /* already closed */ }
            resolve(r);
        };
        const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
            const cert = socket.getPeerCertificate();
            if (!cert || !cert.valid_to) {
                finish({ status: 'unreachable', detail: 'The server sent no certificate.', validTo: null, validFrom: null, issuer: null, trusted: null, trustError: null, names: [] });
                return;
            }
            let authError = socket.authorizationError ? String(socket.authorizationError) : null;
            // With rejectUnauthorized off, Node checks the chain but not the host name, so check it here.
            const nameError = tls.checkServerIdentity(host, cert);
            const trusted = socket.authorized === true && !nameError;
            if (!authError && nameError) authError = 'ERR_TLS_CERT_ALTNAME_INVALID';
            const names = typeof cert.subjectaltname === 'string'
                ? cert.subjectaltname.split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean)
                : [];
            const issuerObj = cert.issuer as unknown as Record<string, string> | undefined;
            finish({
                status: 'ok',
                detail: null,
                validTo: new Date(cert.valid_to).toISOString(),
                validFrom: cert.valid_from ? new Date(cert.valid_from).toISOString() : null,
                issuer: issuerObj ? issuerObj.O || issuerObj.CN || null : null,
                trusted,
                trustError: trusted ? null : authError,
                names,
            });
        });
        socket.on('timeout', () => finish({ status: 'unreachable', detail: `No TLS answer on port ${port} within ${Math.round(timeoutMs / 1000)} s.`, validTo: null, validFrom: null, issuer: null, trusted: null, trustError: null, names: [] }));
        socket.on('error', (e) => finish({ status: 'unreachable', detail: `Could not open a TLS connection on port ${port} (${(e as NodeJS.ErrnoException).code ?? e.message}).`, validTo: null, validFrom: null, issuer: null, trusted: null, trustError: null, names: [] }));
    });
}

/** Plain-words reason for a Node TLS authorisation error code. */
export function explainTrustError(code: string | null): string {
    switch (code) {
        case null: return '';
        case 'CERT_HAS_EXPIRED': return 'certificate has expired';
        case 'DEPTH_ZERO_SELF_SIGNED_CERT':
        case 'SELF_SIGNED_CERT_IN_CHAIN': return 'self-signed certificate, browsers will warn';
        case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
        case 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY': return 'incomplete certificate chain (missing intermediate), some browsers and apps will fail';
        case 'ERR_TLS_CERT_ALTNAME_INVALID': return 'certificate does not cover this host name';
        default: return `certificate not trusted (${code})`;
    }
}
