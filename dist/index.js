var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  PLATFORM_SUFFIXES: () => PLATFORM_SUFFIXES,
  dangerStatuses: () => dangerStatuses,
  daysLeft: () => daysLeft,
  hostOf: () => hostOf2,
  judge: () => judge,
  parseChecks: () => parseChecks,
  platformOf: () => platformOf,
  run: () => run,
  splitList: () => splitList
});
module.exports = __toCommonJS(main_exports);
var import_node_fs = require("node:fs");
var import_node_crypto = require("node:crypto");

// src/rdap.ts
var BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
var USER_AGENT = "domain-expiry-check/1.0 (+https://github.com/Nero-Engine/domain-expiry-check)";
function parseBootstrap(file) {
  const map = /* @__PURE__ */ new Map();
  for (const [tlds, urls] of file.services ?? []) {
    const bases = (urls ?? []).filter((u) => typeof u === "string" && /^https?:\/\//i.test(u)).map((u) => u.replace(/\/+$/, ""));
    if (bases.length === 0) continue;
    for (const tld of tlds ?? []) {
      const key = String(tld).toLowerCase().replace(/^\./, "");
      if (key) map.set(key, bases);
    }
  }
  return map;
}
function vcardField(entity, field) {
  const vcard = entity?.vcardArray;
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return null;
  for (const item of vcard[1]) {
    if (!Array.isArray(item) || item[0] !== field) continue;
    const value = item[3];
    if (typeof value === "string" && value.trim() !== "") return value.trim();
    if (Array.isArray(value)) {
      const joined = value.filter((v) => typeof v === "string" && v.trim() !== "");
      if (field === "adr") return value[6]?.trim() || null;
      if (joined.length > 0) return String(joined[joined.length - 1]).trim();
    }
  }
  return null;
}
function entitiesWithRole(json, role) {
  const out = [];
  const walk = (list, depth) => {
    if (!Array.isArray(list) || depth > 3) return;
    for (const raw of list) {
      if (raw === null || typeof raw !== "object") continue;
      const entity = raw;
      const roles = Array.isArray(entity.roles) ? entity.roles.map((r) => String(r).toLowerCase()) : [];
      if (roles.includes(role)) out.push(entity);
      walk(entity.entities, depth + 1);
    }
  };
  walk(json.entities, 0);
  return out;
}
function eventDate(json, action) {
  const events = Array.isArray(json.events) ? json.events : [];
  for (const raw of events) {
    if (raw === null || typeof raw !== "object") continue;
    const event = raw;
    if (String(event.eventAction ?? "").toLowerCase() !== action) continue;
    const date = String(event.eventDate ?? "");
    const parsed = new Date(date);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return null;
}
function parseRdap(json) {
  const registrar = entitiesWithRole(json, "registrar")[0] ?? null;
  const registrant = entitiesWithRole(json, "registrant")[0] ?? null;
  let registrarIanaId = null;
  const publicIds = registrar?.publicIds;
  if (Array.isArray(publicIds)) {
    for (const raw of publicIds) {
      if (raw === null || typeof raw !== "object") continue;
      const id = raw;
      if (/iana/i.test(String(id.type ?? ""))) registrarIanaId = String(id.identifier ?? "") || null;
    }
  }
  const nameservers = (Array.isArray(json.nameservers) ? json.nameservers : []).map((raw) => raw !== null && typeof raw === "object" ? String(raw.ldhName ?? "") : "").filter((n) => n !== "").map((n) => n.toLowerCase().replace(/\.$/, ""));
  const statuses = (Array.isArray(json.status) ? json.status : []).map((s) => String(s)).filter((s) => s !== "");
  const secureDns = json.secureDNS;
  const dnssec = secureDns && typeof secureDns.delegationSigned === "boolean" ? secureDns.delegationSigned : null;
  const registrantOrganization = registrant ? vcardField(registrant, "org") : null;
  const registrantCountry = registrant ? vcardField(registrant, "adr") : null;
  return {
    ldhName: typeof json.ldhName === "string" ? json.ldhName.toLowerCase() : null,
    registeredOn: eventDate(json, "registration"),
    expiresOn: eventDate(json, "expiration"),
    lastChangedOn: eventDate(json, "last changed"),
    registrar: registrar ? vcardField(registrar, "fn") : null,
    registrarIanaId,
    nameservers: [...new Set(nameservers)],
    statuses,
    dnssec,
    registrantOrganization,
    registrantCountry: registrantCountry && /^[A-Za-z]{2,3}$/.test(registrantCountry) ? registrantCountry.toUpperCase() : registrantCountry,
    contactDataRedacted: registrantOrganization === null
  };
}
var HostThrottle = class {
  constructor(gapMs) {
    this.gapMs = gapMs;
  }
  gapMs;
  nextFreeAt = /* @__PURE__ */ new Map();
  async take(host) {
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
};
async function defaultSleep(ms) {
  await new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
var BLOCKED_RDAP_HOST_SUFFIXES = ["nominet.uk"];
var BLOCKED_TLDS = /* @__PURE__ */ new Set(["uk", "cymru", "wales"]);
function hostIsBlocked(base) {
  let host;
  try {
    host = new URL(base).hostname.toLowerCase();
  } catch {
    return false;
  }
  return BLOCKED_RDAP_HOST_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}
function isBlockedByRegistryTerms(tld, servers) {
  if (BLOCKED_TLDS.has(tld)) return true;
  return (servers.get(tld) ?? []).some(hostIsBlocked);
}
function registryTermsDetail(tld) {
  if (tld === "uk") return "Not checked: the .uk registry (Nominet) does not permit commercial automated lookups. Not charged.";
  return `Not checked: the .${tld} registry's RDAP server is run by Nominet, whose terms do not permit commercial automated lookups. Not charged.`;
}
async function lookupDomain(domain, tld, options) {
  if (isBlockedByRegistryTerms(tld, options.servers)) {
    return { status: "not_checked_registry_terms", statusDetail: registryTermsDetail(tld), record: null, rdapServer: null, attempts: 0 };
  }
  const bases = options.servers.get(tld);
  if (!bases || bases.length === 0) {
    return {
      status: "no_rdap_server",
      statusDetail: `The .${tld} registry does not publish an RDAP server, so no authoritative record could be read. Not charged.`,
      record: null,
      rdapServer: null,
      attempts: 0
    };
  }
  const maxRetries = options.maxRetries ?? 2;
  const sleep = options.sleep ?? defaultSleep;
  let attempts = 0;
  let lastDetail = "The registry did not answer.";
  let lastStatus = "unreachable";
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
          redirect: "follow",
          headers: { accept: "application/rdap+json, application/json", "user-agent": USER_AGENT }
        });
        if (response.status === 200) {
          const json = await response.json();
          return { status: "ok", statusDetail: null, record: parseRdap(json), rdapServer: base, attempts };
        }
        if (response.status === 404) {
          return {
            status: "not_registered",
            statusDetail: "The registry has no record for this domain, so it is not currently registered.",
            record: null,
            rdapServer: base,
            attempts
          };
        }
        if (response.status === 429) {
          lastStatus = "rate_limited";
          lastDetail = `The .${tld} registry is rate-limiting this run (HTTP 429). Not charged. Lower 'Concurrency' or split the list across runs.`;
          const retryAfter = Number(response.headers.get("retry-after") ?? "0");
          const backoffMs = retryAfter > 0 ? Math.min(retryAfter * 1e3, 3e4) : 1e3 * 2 ** attempt;
          if (attempt < maxRetries) {
            await sleep(backoffMs);
            continue;
          }
          break;
        }
        if (response.status === 403 || response.status === 401) {
          lastStatus = "refused";
          lastDetail = `The .${tld} registry refused the request (HTTP ${response.status}). Some registries only answer RDAP for approved clients. Not charged.`;
          break;
        }
        if (response.status >= 500) {
          lastStatus = "server_error";
          lastDetail = `The .${tld} registry's RDAP server returned HTTP ${response.status}. Not charged.`;
          if (attempt < maxRetries) {
            await sleep(500 * 2 ** attempt);
            continue;
          }
          break;
        }
        lastStatus = "server_error";
        lastDetail = `The registry responded with HTTP ${response.status}. Not charged.`;
        break;
      } catch (e) {
        lastStatus = "unreachable";
        const message = e.name === "AbortError" ? `timed out after ${Math.round(options.timeoutMs / 1e3)}s` : e.message;
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
async function loadServers(fetchImpl, timeoutMs) {
  let lastError = "";
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(BOOTSTRAP_URL, {
        signal: controller.signal,
        redirect: "follow",
        headers: { accept: "application/json", "user-agent": USER_AGENT }
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const file = await response.json();
      const servers = parseBootstrap(file);
      if (servers.size === 0) throw new Error("the file listed no RDAP servers");
      return { servers, publication: file.publication ?? null };
    } catch (e) {
      lastError = e.message;
      await defaultSleep(500 * 2 ** attempt);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(`Could not download IANA's RDAP server list from ${BOOTSTRAP_URL} (${lastError}). This run cannot look up any domain without it; try again shortly.`);
}

// src/domain.ts
var SECOND_LEVEL = /* @__PURE__ */ new Set(["co", "com", "org", "net", "gov", "edu", "ac", "ltd", "plc", "sch", "nhs", "mod", "me"]);
function registrableDomain(raw) {
  if (raw === null || raw === void 0) return null;
  let value = String(raw).trim().toLowerCase();
  if (value === "") return null;
  value = value.replace(/^mailto:/i, "").replace(/\s+/g, "");
  if (/^[^@/]+@[^@/]+\.[a-z]{2,}$/i.test(value)) value = value.split("@")[1];
  if (value.includes("://")) {
    try {
      value = new URL(value).hostname;
    } catch {
      return null;
    }
  }
  const host = value.replace(/^www\./, "").replace(/\.$/, "").split("/")[0].split("?")[0].split("#")[0].split(":")[0];
  if (!host.includes(".")) return null;
  if (!/^[a-z0-9.-]+$/.test(host)) return null;
  const labels = host.split(".");
  if (labels.some((l) => l === "" || l.length > 63)) return null;
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld)) return null;
  if (labels.length <= 2) return labels.join(".");
  const secondLast = labels[labels.length - 2];
  return labels.slice(SECOND_LEVEL.has(secondLast) ? -3 : -2).join(".");
}
function tldOf(domain) {
  return domain.split(".").pop() ?? "";
}

// src/ssl.ts
var import_node_tls = __toESM(require("node:tls"));
function checkSsl(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      try {
        socket.destroy();
      } catch {
      }
      resolve(r);
    };
    const socket = import_node_tls.default.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const cert = socket.getPeerCertificate();
      if (!cert || !cert.valid_to) {
        finish({ status: "unreachable", detail: "The server sent no certificate.", validTo: null, validFrom: null, issuer: null, trusted: null, trustError: null, names: [] });
        return;
      }
      let authError = socket.authorizationError ? String(socket.authorizationError) : null;
      const nameError = import_node_tls.default.checkServerIdentity(host, cert);
      const trusted = socket.authorized === true && !nameError;
      if (!authError && nameError) authError = "ERR_TLS_CERT_ALTNAME_INVALID";
      const names = typeof cert.subjectaltname === "string" ? cert.subjectaltname.split(",").map((s) => s.trim().replace(/^DNS:/, "")).filter(Boolean) : [];
      const issuerObj = cert.issuer;
      finish({
        status: "ok",
        detail: null,
        validTo: new Date(cert.valid_to).toISOString(),
        validFrom: cert.valid_from ? new Date(cert.valid_from).toISOString() : null,
        issuer: issuerObj ? issuerObj.O || issuerObj.CN || null : null,
        trusted,
        trustError: trusted ? null : authError,
        names
      });
    });
    socket.on("timeout", () => finish({ status: "unreachable", detail: `No TLS answer on port ${port} within ${Math.round(timeoutMs / 1e3)} s.`, validTo: null, validFrom: null, issuer: null, trusted: null, trustError: null, names: [] }));
    socket.on("error", (e) => finish({ status: "unreachable", detail: `Could not open a TLS connection on port ${port} (${e.code ?? e.message}).`, validTo: null, validFrom: null, issuer: null, trusted: null, trustError: null, names: [] }));
  });
}
function explainTrustError(code) {
  switch (code) {
    case null:
      return "";
    case "CERT_HAS_EXPIRED":
      return "certificate has expired";
    case "DEPTH_ZERO_SELF_SIGNED_CERT":
    case "SELF_SIGNED_CERT_IN_CHAIN":
      return "self-signed certificate, browsers will warn";
    case "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
    case "UNABLE_TO_GET_ISSUER_CERT_LOCALLY":
      return "incomplete certificate chain (missing intermediate), some browsers and apps will fail";
    case "ERR_TLS_CERT_ALTNAME_INVALID":
      return "certificate does not cover this host name";
    default:
      return `certificate not trusted (${code})`;
  }
}

// src/main.ts
var VERSION = "1.0.0";
var ACTOR_URL = "https://apify.com/nerolabs/domain-whois-checker";
var REPO_URL = "https://github.com/Nero-Engine/domain-expiry-check";
var HARD_MAX = 200;
var DAY_MS = 864e5;
var PLATFORM_SUFFIXES = ["github.io", "workers.dev", "pages.dev", "vercel.app", "netlify.app", "herokuapp.com", "web.app", "firebaseapp.com", "azurewebsites.net", "cloudfront.net", "onrender.com", "fly.dev", "railway.app", "blogspot.com", "wordpress.com", "myshopify.com", "wixsite.com", "squarespace.com", "webflow.io", "framer.app", "appspot.com", "amplifyapp.com", "surge.sh", "gitlab.io", "replit.app", "deno.dev", "supabase.co"];
function platformOf(host) {
  return PLATFORM_SUFFIXES.find((s) => host === s || host.endsWith(`.${s}`)) ?? null;
}
var inActions = process.env.GITHUB_ACTIONS === "true";
function input(name, fallback = "") {
  const v = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`];
  return v === void 0 || v.trim() === "" ? fallback : v.trim();
}
function splitList(v) {
  return v.split(/\r?\n/).map((line) => line.replace(/#.*$/, "")).join(" ").split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
}
function clampInt(v, def, min, max) {
  const n = Math.round(Number(v));
  return Number.isFinite(n) && v !== "" ? Math.min(Math.max(n, min), max) : def;
}
function parseChecks(v) {
  const s = v.toLowerCase();
  if (s === "domain" || s === "registration") return ["domain"];
  if (s === "ssl" || s === "tls" || s === "certificate") return ["ssl"];
  return ["domain", "ssl"];
}
function hostOf2(raw) {
  let s = raw.trim().toLowerCase();
  if (!s) return null;
  if (/^[^@/]+@[^@/]+\.[a-z]{2,}$/i.test(s)) s = s.split("@")[1];
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    const h = u.hostname.replace(/\.$/, "");
    if (!h.includes(".") || !/^[a-z0-9.-]+$/.test(h) || /^\d+(\.\d+){3}$/.test(h)) return null;
    if (!/^[a-z]{2,}$/.test(h.split(".").pop() ?? "")) return null;
    return h;
  } catch {
    return null;
  }
}
function readOptions() {
  if (inActions) {
    return {
      hosts: splitList(input("domains")),
      file: input("domains-file") || null,
      checks: parseChecks(input("check", "both")),
      failDays: clampInt(input("fail-within-days"), 30, 0, 3650),
      warnDays: clampInt(input("warn-within-days"), 60, 0, 3650),
      sslFailDays: clampInt(input("ssl-fail-within-days"), 14, 0, 3650),
      failOnProblems: !/^(false|no|0|off)$/i.test(input("fail-on-problems", "true")),
      sslPort: clampInt(input("ssl-port"), 443, 1, 65535),
      timeoutMs: clampInt(input("timeout-seconds"), 20, 5, 120) * 1e3
    };
  }
  const args = process.argv.slice(2);
  const o = { hosts: [], file: null, checks: ["domain", "ssl"], failDays: 30, warnDays: 60, sslFailDays: 14, failOnProblems: true, sslPort: 443, timeoutMs: 2e4 };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--file") o.file = args[++i] ?? null;
    else if (a === "--check") o.checks = parseChecks(args[++i] ?? "both");
    else if (a === "--fail-within-days") o.failDays = clampInt(args[++i] ?? "", 30, 0, 3650);
    else if (a === "--warn-within-days") o.warnDays = clampInt(args[++i] ?? "", 60, 0, 3650);
    else if (a === "--ssl-fail-within-days") o.sslFailDays = clampInt(args[++i] ?? "", 14, 0, 3650);
    else if (a === "--no-fail-on-problems") o.failOnProblems = false;
    else if (a === "--port") o.sslPort = clampInt(args[++i] ?? "", 443, 1, 65535);
    else if (a === "--help" || a === "-h") {
      console.log("Usage: node dist/index.js <domain> [domain...] [--file domains.txt] [--check both|domain|ssl] [--fail-within-days 30] [--ssl-fail-within-days 14] [--warn-within-days 60] [--no-fail-on-problems] [--port 443]");
      process.exit(0);
    } else o.hosts.push(...splitList(a));
  }
  return o;
}
function escapeData(s) {
  return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function warn(msg) {
  console.log(inActions ? `::warning::${escapeData(msg)}` : `WARNING: ${msg}`);
}
function annotate(level, title, msg) {
  if (inActions) console.log(`::${level} title=${escapeData(title).replace(/:/g, "%3A").replace(/,/g, "%2C")}::${escapeData(msg)}`);
}
function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  const delim = `EOF_${(0, import_node_crypto.randomBytes)(8).toString("hex")}`;
  (0, import_node_fs.appendFileSync)(file, `${name}<<${delim}
${value}
${delim}
`);
}
function summary(md) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (file) (0, import_node_fs.appendFileSync)(file, md);
}
function fatal(msg) {
  if (inActions) console.log(`::error::${escapeData(msg)}`);
  else console.error(msg);
  setOutput("result", "error");
  summary(`## Domain Expiry Check

**Not run:** ${msg}
`);
  process.exitCode = 1;
}
function daysLeft(iso, now) {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? null : Math.floor((t - now) / DAY_MS);
}
function dangerStatuses(statuses) {
  return statuses.filter((s) => /hold|redemption|pending ?delete|pending ?restore|inactive/i.test(s));
}
function judge(row, o) {
  const fail = [];
  const soft = [];
  const when = (d) => d < 0 ? `expired ${-d} day(s) ago` : d === 0 ? "expires today" : `expires in ${d} day(s)`;
  if (row.domainDaysLeft !== null) {
    if (row.domainDaysLeft <= o.failDays) fail.push(`Domain registration ${when(row.domainDaysLeft)} (${row.domainExpiresOn?.slice(0, 10)})${row.registrar ? `, registrar ${row.registrar}` : ""}`);
    else if (row.domainDaysLeft <= o.warnDays) soft.push(`Domain registration ${when(row.domainDaysLeft)}`);
  }
  if (row.sslDaysLeft !== null) {
    if (row.sslDaysLeft <= o.sslFailDays) fail.push(`TLS certificate ${when(row.sslDaysLeft)} (${row.sslExpiresOn?.slice(0, 10)})${row.sslIssuer ? `, issuer ${row.sslIssuer}` : ""}`);
    else if (row.sslDaysLeft <= o.sslFailDays + 7) soft.push(`TLS certificate ${when(row.sslDaysLeft)}`);
  }
  const problems = [];
  if (row.sslTrusted === false && !(row.sslDaysLeft !== null && row.sslDaysLeft < 0)) problems.push(`TLS ${row.sslDetail ?? "certificate not trusted"}`);
  const danger = dangerStatuses(row.registryStatuses);
  if (danger.length) problems.push(`Registry status: ${danger.join(", ")}`);
  if (row.domainStatus === "not_registered") problems.push("Domain is not registered (lapsed or never bought)");
  if (o.failOnProblems) fail.push(...problems);
  else soft.push(...problems);
  if (row.sslStatus === "unreachable") soft.push(`TLS not checked: ${row.sslDetail}`);
  if (row.domainStatus !== "ok" && row.domainStatus !== "not_registered" && row.domainStatus !== "skipped" && row.domainStatus !== "platform") soft.push(`Registration date not read: ${row.domainDetail}`);
  row.failing = fail;
  row.warnings = soft;
}
var dayCell = (d) => d === null ? "" : `${d <= 14 ? "\u{1F534}" : d <= 30 ? "\u{1F7E0}" : d <= 60 ? "\u{1F7E1}" : "\u{1F7E2}"} ${d}`;
var pipe = (s) => s.replace(/\|/g, "/");
function domainCell(r) {
  if (r.domainStatus === "skipped") return "";
  if (r.domainStatus === "ok") return `${r.domainExpiresOn?.slice(0, 10) ?? "no date published"}`;
  if (r.domainStatus === "not_registered") return "\u274C not registered";
  if (r.domainStatus === "platform") return "\u2796 platform domain";
  return `\u2796 ${r.domainStatus === "no_rdap_server" ? "registry has no RDAP" : r.domainStatus === "not_checked_registry_terms" ? "not checked (registry terms)" : r.domainStatus}`;
}
function markdown(rows, o, failed) {
  const lines = ["## Domain Expiry Check", ""];
  const checks = o.checks.map((c) => c === "domain" ? "domain registration" : "TLS certificate").join(" + ");
  lines.push(`**Result: ${failed ? "failing" : "passing"}** \xB7 checks: ${checks} \xB7 fails when a domain expires within **${o.failDays} days** or a certificate within **${o.sslFailDays} days**${o.failOnProblems ? ", a certificate is not trusted, or a domain is on hold, in redemption or not registered" : ""} \xB7 ${rows.length} host(s)`, "");
  lines.push("| Host | Domain expires | Days left | Registrar | TLS expires | Days left | Issuer | Notes |", "|---|---|---|---|---|---|---|---|");
  const sorted = [...rows].sort((a, b) => b.failing.length - a.failing.length || Math.min(a.domainDaysLeft ?? 1e9, a.sslDaysLeft ?? 1e9) - Math.min(b.domainDaysLeft ?? 1e9, b.sslDaysLeft ?? 1e9));
  for (const r of sorted) {
    const tls2 = r.sslStatus === "skipped" ? "" : r.sslStatus === "ok" ? `${r.sslExpiresOn?.slice(0, 10)}${r.sslTrusted === false ? " \u26A0\uFE0F" : ""}` : "\u2796 no answer";
    const notes = [...r.failing.map((f) => `\u2757 ${f}`), ...r.warnings].join("; ");
    lines.push(`| ${r.host}${r.failing.length ? " \u2757" : ""} | ${domainCell(r)} | ${dayCell(r.domainDaysLeft)} | ${pipe(r.registrar ?? "")} | ${tls2} | ${dayCell(r.sslDaysLeft)} | ${pipe(r.sslIssuer ?? "")} | ${pipe(notes).slice(0, 300)} |`);
  }
  lines.push("", "<sub>Domain dates come from the registry's own RDAP server (the official replacement for WHOIS, listed by IANA), never guessed. Some endings (for example .de, .ie) publish no RDAP server, and .uk is not queried because Nominet's terms do not allow automated lookups, so only the certificate is checked for those. Run this on a weekly `schedule`: GitHub emails you when a scheduled run fails.</sub>", "");
  lines.push(`<sub>Hundreds of domains, from a CSV, Google Sheet or spreadsheet, or checking which name ideas are still free? [Domain WHOIS & Age Checker on Apify](${ACTOR_URL}) reads the same registry records in bulk, filters to the ones expiring soon or newly registered and exports CSV or Excel.</sub>`, "");
  return lines.join("\n");
}
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  }));
  return out;
}
async function run(o, now = Date.now()) {
  const raw = [...o.hosts];
  if (o.file) {
    try {
      raw.push(...splitList((0, import_node_fs.readFileSync)(o.file, "utf8")));
    } catch (e) {
      fatal(`Could not read domains-file ${o.file}: ${e.message}`);
      return null;
    }
  }
  const hosts = [];
  const seen = /* @__PURE__ */ new Set();
  for (const r of raw) {
    const h = hostOf2(r);
    if (!h) {
      warn(`Skipped, not a domain or host name: ${r}`);
      continue;
    }
    if (!seen.has(h)) {
      seen.add(h);
      hosts.push(h);
    }
  }
  if (hosts.length === 0) {
    fatal("No domains to check. Set `domains` (one per line or comma separated) or `domains-file` (a text file in your repo, one per line).");
    return null;
  }
  if (hosts.length > HARD_MAX) warn(`${hosts.length} hosts given; checking the first ${HARD_MAX}. For bigger lists use ${ACTOR_URL}.`);
  const list = hosts.slice(0, HARD_MAX);
  console.log(`Domain Expiry Check v${VERSION}: ${list.length} host(s), checks ${o.checks.join("+")}, fail within ${o.failDays} days (certificates ${o.sslFailDays})`);
  const lookups = /* @__PURE__ */ new Map();
  if (o.checks.includes("domain")) {
    let servers = null;
    try {
      servers = (await loadServers(fetch, o.timeoutMs)).servers;
    } catch (e) {
      warn(e.message);
    }
    const domains = [...new Set(list.filter((h) => !platformOf(h)).map((h) => registrableDomain(h)).filter((d) => !!d))];
    if (servers) {
      const throttle = new HostThrottle(400);
      const srv = servers;
      await mapLimit(domains, 4, async (d) => {
        lookups.set(d, await lookupDomain(d, tldOf(d), { servers: srv, fetchImpl: fetch, timeoutMs: o.timeoutMs, throttle }));
      });
    } else {
      for (const d of domains) lookups.set(d, { status: "unreachable", statusDetail: "IANA RDAP list could not be downloaded.", record: null, rdapServer: null, attempts: 0 });
    }
  }
  const ssl = /* @__PURE__ */ new Map();
  if (o.checks.includes("ssl")) {
    await mapLimit(list, 8, async (h) => {
      let r = await checkSsl(h, o.sslPort, o.timeoutMs);
      if (r.status === "unreachable") {
        await new Promise((ok) => setTimeout(ok, 1500));
        r = await checkSsl(h, o.sslPort, o.timeoutMs);
      }
      ssl.set(h, r);
    });
  }
  return list.map((host) => {
    const platform = platformOf(host);
    const domain = platform ? null : registrableDomain(host);
    const lk = domain ? lookups.get(domain) : void 0;
    const s = ssl.get(host);
    const rec = lk?.record ?? null;
    const row = {
      host,
      domain,
      domainStatus: !o.checks.includes("domain") ? "skipped" : platform ? "platform" : lk?.status ?? "invalid_domain",
      domainDetail: platform ? `${platform} is a shared platform domain, renewed by the platform` : lk?.statusDetail?.replace(/ Not charged\.$/, "").replace(/ Lower 'Concurrency'.*$/, "") ?? null,
      domainExpiresOn: rec?.expiresOn ?? null,
      domainDaysLeft: daysLeft(rec?.expiresOn ?? null, now),
      registrar: rec?.registrar ?? null,
      registryStatuses: rec?.statuses ?? [],
      sslStatus: s ? s.status : "skipped",
      sslDetail: s ? s.status === "ok" ? s.trusted === false ? explainTrustError(s.trustError) : null : s.detail : null,
      sslExpiresOn: s?.validTo ?? null,
      sslDaysLeft: daysLeft(s?.validTo ?? null, now),
      sslIssuer: s?.issuer ?? null,
      sslTrusted: s?.trusted ?? null,
      failing: [],
      warnings: []
    };
    judge(row, o);
    return row;
  });
}
async function main() {
  const o = readOptions();
  const rows = await run(o);
  if (!rows) return;
  for (const r of rows) {
    for (const f of r.failing) annotate("error", "Domain Expiry Check", `${r.host}: ${f}`);
    for (const w of r.warnings) annotate("warning", "Domain Expiry Check", `${r.host}: ${w}`);
  }
  const failedRows = rows.filter((r) => r.failing.length > 0);
  const checked = rows.filter((r) => r.domainDaysLeft !== null || r.sslDaysLeft !== null || r.domainStatus === "not_registered");
  const failed = failedRows.length > 0;
  const allDays = rows.flatMap((r) => [r.domainDaysLeft, r.sslDaysLeft]).filter((d) => d !== null);
  const soonest = allDays.length ? Math.min(...allDays) : null;
  const result = failed ? "fail" : checked.length === 0 ? "error" : "pass";
  setOutput("result", result);
  setOutput("failing-count", String(failedRows.length));
  setOutput("failing-hosts", failedRows.map((r) => r.host).join(","));
  setOutput("soonest-days-left", soonest === null ? "" : String(soonest));
  setOutput("report", JSON.stringify(rows));
  summary(markdown(rows, o, failed));
  console.log("");
  for (const r of rows) {
    const d = r.domainStatus === "skipped" ? "" : `domain ${r.domainDaysLeft === null ? r.domainStatus : `${r.domainDaysLeft}d`}`;
    const t = r.sslStatus === "skipped" ? "" : `tls ${r.sslDaysLeft === null ? r.sslStatus : `${r.sslDaysLeft}d`}${r.sslTrusted === false ? " (untrusted)" : ""}`;
    console.log(`${r.failing.length ? "!" : " "} ${`${d}  ${t}`.trim().padEnd(34)} ${r.host}`);
    for (const f of r.failing) console.log(`      ${f}`);
  }
  console.log(`
${result.toUpperCase()}: ${failedRows.length} failing of ${rows.length} host(s); soonest expiry in ${soonest ?? "n/a"} day(s).`);
  console.log(`Bulk lists, CSV or Sheet input and name-idea checks: ${ACTOR_URL}  (${REPO_URL})`);
  if (result !== "pass") process.exitCode = 1;
}
if (process.env.DOMAIN_EXPIRY_NO_MAIN !== "1") {
  main().catch((err) => fatal(`Domain Expiry Check crashed: ${err.message}`));
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  PLATFORM_SUFFIXES,
  dangerStatuses,
  daysLeft,
  hostOf,
  judge,
  parseChecks,
  platformOf,
  run,
  splitList
});
