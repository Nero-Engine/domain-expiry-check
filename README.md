# Domain Expiry Check: Domain & SSL Certificate Alerts

**A lapsed domain or an expired certificate takes your site, email and checkout down at once, and the renewal email usually went to someone who left.** This GitHub Action checks every domain and host you list, once a week, and fails the run before anything expires. GitHub emails you when a scheduled run fails, so it is a free expiry alert with no server, no account and no API key.

## What it checks
For each domain or host name:
- **Domain registration expiry**, read from the registry's own RDAP server (the official replacement for WHOIS, found through IANA's list). Never scraped, never guessed. Also the registrar and the registry status.
- **TLS (SSL) certificate expiry** of the host, plus whether browsers trust it: self-signed, wrong host name, or a missing intermediate certificate all count as problems.
- **Danger statuses**: a domain on hold, in redemption, pending delete, or no longer registered at all.

It writes a job summary table sorted by what needs you first, an annotation per problem, step outputs, and fails the step when anything is inside your window.

## Quick start
```yaml
# .github/workflows/domain-expiry.yml
name: Domain and SSL expiry
on:
  schedule:
    - cron: '0 7 * * 1'   # every Monday
  workflow_dispatch:
jobs:
  expiry:
    runs-on: ubuntu-latest
    steps:
      - uses: Nero-Engine/domain-expiry-check@v1
        with:
          domains: |
            example.com
            www.example.com
            shop.example.com
          fail-within-days: 30
```
Keep a longer list in a file instead: add `actions/checkout@v4` first and use `domains-file: .github/domains.txt` (one per line, `#` comments allowed).

## Inputs
| Input | Default | What it does |
|---|---|---|
| `domains` | | Domains, hosts or URLs, one per line or comma separated. |
| `domains-file` | | Text file in your repo, one per line. |
| `check` | `both` | `both`, `domain` (registration only) or `ssl` (certificate only). |
| `fail-within-days` | `30` | Fail when a domain registration expires within this many days. `0` = only when already expired. |
| `ssl-fail-within-days` | `14` | Fail when a certificate expires within this many days (warns 7 days earlier). Shorter by default because Let's Encrypt and other automated certificates renew themselves at 30 days left, so a stuck renewal shows up here. |
| `warn-within-days` | `60` | Warning annotation (not a failure) when a domain registration expires inside this window. |
| `fail-on-problems` | `true` | Also fail on an untrusted certificate and on hold, redemption or unregistered domains. `false` = warn only. |
| `ssl-port` | `443` | Port to read the certificate from. |
| `timeout-seconds` | `20` | Per lookup timeout. |

## Outputs
| Output | Meaning |
|---|---|
| `result` | `pass`, `fail` or `error` (nothing could be checked). |
| `failing-count` | Hosts that failed. |
| `failing-hosts` | Comma separated hosts that failed. |
| `soonest-days-left` | Days to the soonest expiry across everything (negative = already expired). |
| `report` | Full JSON: per host the dates, days left, registrar, statuses, issuer, trust and reasons. |

Use the outputs to post to Slack or open an issue, for example `if: steps.check.outputs.result == 'fail'`.

## Run it locally
```bash
node dist/index.js example.com www.example.com --fail-within-days 30
```
Flags: `--file domains.txt`, `--ssl-fail-within-days 14`, `--check both|domain|ssl`, `--warn-within-days 60`, `--no-fail-on-problems`, `--port 443`. Exit code 1 means something needs you.

## Accuracy notes
- Dates come only from the registry's RDAP record. Some endings publish no RDAP server (for example `.de`, `.ie`); for those the certificate is still checked and the summary says why the registration date is missing.
- `.uk` domains are not queried: Nominet's terms do not allow automated lookups. Their certificates are checked.
- Hosts on shared platforms (`*.github.io`, `*.workers.dev`, `*.vercel.app`, `*.netlify.app` and similar) only get the certificate checked, because the platform owns and renews the domain.
- Requests to each registry are spaced out, because registries rate-limit. Up to 200 hosts per run.

## Hundreds of domains, or a spreadsheet?
For a portfolio of client or brand domains in a CSV, Google Sheet or spreadsheet, to find the ones expiring soon or newly registered, or to check which name ideas are still free across endings, use **[Domain WHOIS & Age Checker on Apify](https://apify.com/nerolabs/domain-whois-checker)**. It reads the same registry records in bulk, filters, and exports CSV or Excel, on a schedule if you like.

## Licence
MIT. Made by Nero Labs.
