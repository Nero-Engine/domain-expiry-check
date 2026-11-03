// Unit tests for the pure parts, plus one CLI run that must fail on an expired certificate date.
const assert = require('node:assert/strict');
process.env.DOMAIN_EXPIRY_NO_MAIN = '1';
const m = require('../dist/index.js');
let n = 0;
const t = (name, fn) => { fn(); n += 1; console.log(`ok ${n} ${name}`); };

t('hostOf reads domains, hosts, URLs and emails', () => {
    assert.equal(m.hostOf('Example.COM'), 'example.com');
    assert.equal(m.hostOf('https://shop.example.co.uk/path?q=1'), 'shop.example.co.uk');
    assert.equal(m.hostOf('admin@example.org'), 'example.org');
    assert.equal(m.hostOf('localhost'), null);
    assert.equal(m.hostOf('192.168.1.1'), null);
    assert.equal(m.hostOf('9.99'), null);
});
t('splitList drops comments and blank lines', () => {
    assert.deepEqual(m.splitList('a.com, b.com\n# note\nc.com # main site\n\n'), ['a.com', 'b.com', 'c.com']);
});
t('parseChecks', () => {
    assert.deepEqual(m.parseChecks('both'), ['domain', 'ssl']);
    assert.deepEqual(m.parseChecks('SSL'), ['ssl']);
    assert.deepEqual(m.parseChecks('domain'), ['domain']);
});
t('daysLeft floors and handles past dates', () => {
    const now = Date.parse('2026-11-03T00:00:00Z');
    assert.equal(m.daysLeft('2026-11-13T12:00:00Z', now), 10);
    assert.equal(m.daysLeft('2026-11-01T00:00:00Z', now), -2);
    assert.equal(m.daysLeft(null, now), null);
});
t('platform hosts skip the registration check', () => {
    assert.equal(m.platformOf('me.github.io'), 'github.io');
    assert.equal(m.platformOf('x.y.workers.dev'), 'workers.dev');
    assert.equal(m.platformOf('github.com'), null);
});
t('danger statuses', () => {
    assert.deepEqual(m.dangerStatuses(['client transfer prohibited', 'redemption period', 'server hold']), ['redemption period', 'server hold']);
});
const base = { host: 'a.com', domain: 'a.com', domainStatus: 'ok', domainDetail: null, domainExpiresOn: '2026-11-20T00:00:00Z', domainDaysLeft: 17, registrar: 'R', registryStatuses: [], sslStatus: 'ok', sslDetail: null, sslExpiresOn: '2027-06-01T00:00:00Z', sslDaysLeft: 200, sslIssuer: "Let's Encrypt", sslTrusted: true, failing: [], warnings: [] };
const opts = { failDays: 30, warnDays: 60, sslFailDays: 14, failOnProblems: true };
t('judge fails a domain inside the window', () => {
    const r = { ...base }; m.judge(r, opts);
    assert.equal(r.failing.length, 1); assert.match(r.failing[0], /expires in 17 day/);
});
t('judge warns between fail and warn windows', () => {
    const r = { ...base, domainDaysLeft: 45 }; m.judge(r, opts);
    assert.equal(r.failing.length, 0); assert.equal(r.warnings.length, 1);
});
t('judge fails untrusted certificate unless problems are warn-only', () => {
    const r = { ...base, domainDaysLeft: 300, sslTrusted: false, sslDetail: 'self-signed certificate' }; m.judge(r, opts);
    assert.equal(r.failing.length, 1);
    const r2 = { ...base, domainDaysLeft: 300, sslTrusted: false, sslDetail: 'x' }; m.judge(r2, { ...opts, failOnProblems: false });
    assert.equal(r2.failing.length, 0); assert.equal(r2.warnings.length, 1);
});
t('judge fails a lapsed domain and a redemption status', () => {
    const r = { ...base, domainStatus: 'not_registered', domainDaysLeft: null, domainExpiresOn: null }; m.judge(r, opts);
    assert.match(r.failing.join(), /not registered/);
    const r2 = { ...base, domainDaysLeft: 300, registryStatuses: ['redemption period'] }; m.judge(r2, opts);
    assert.match(r2.failing.join(), /redemption/);
});
t('judge does not double-count an expired certificate', () => {
    const r = { ...base, domainDaysLeft: 300, sslDaysLeft: -5, sslTrusted: false, sslDetail: 'certificate has expired' }; m.judge(r, opts);
    assert.equal(r.failing.length, 1); assert.match(r.failing[0], /expired 5 day/);
});
t('certificate window is separate and shorter', () => {
    const r = { ...base, domainDaysLeft: 300, sslDaysLeft: 20 }; m.judge(r, opts);
    assert.equal(r.failing.length, 0); assert.match(r.warnings.join(), /TLS certificate expires in 20/);
    const r2 = { ...base, domainDaysLeft: 300, sslDaysLeft: 12 }; m.judge(r2, opts);
    assert.equal(r2.failing.length, 1);
    const r3 = { ...base, domainDaysLeft: 300, sslDaysLeft: 45 }; m.judge(r3, opts);
    assert.equal(r3.warnings.length, 0);
});
console.log(`\n${n} tests passed`);
