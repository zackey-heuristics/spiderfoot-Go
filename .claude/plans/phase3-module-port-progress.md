# Phase 3: Python → Go Module Port — Progress & Handoff

This file tracks progress on porting all 234 Python SpiderFoot modules to Go.
It is intended as a handoff document so a fresh Claude Code session can resume
without replaying the original planning conversation.

## Current Status

**Completed batches** (commits on `feature/1-go-rewrite`):

| Batch | Commit | Modules | Notes |
|-------|--------|---------|-------|
| 0 — sflib utility package | `f92ee788` | (9 utility files) | httpclient, dns, extract, html, ssl, country, ratelimit, toolexec, netutil |
| 1 — Core DNS | `521e9864` | dns_brute, dns_commonsrv, dns_neighbor, dns_raw, dns_zonexfer, stor_stdout | 6 modules |
| 2 — Network/SSL/WHOIS/Web | `b7113f42` | portscan_tcp, sslcert, whois, spider, webframework, webserver, pageinfo, strangeheaders | 8 modules |
| 3 — Content text extractors | `1d112a87` | email, bitcoin, ethereum, creditcard, iban, phone, names, errors, binstring, hashes, base64, cookie | 12 modules |
| 4 — Content/Web/File | `531a435f` | company, countryname, intfiles, junkfiles, webanalytics, pgp, similar, filemeta | 8 modules |
| 5 — Public DNS Resolvers | `2a909f11` | adguard_dns, cleanbrowsing, cloudflaredns, comodo, opendns, quad9, yandexdns | 7 modules (shared `publicDNSResolver` generic) |
| 6 — DNS/IP Blacklists | `ed1d6721` | spamhaus, sorbs, spamcop, uceprotect, dronebl, surbl | 6 modules (shared `ipDNSBL` generic; surbl also handles domains) |
| 7 — Free APIs Part 1 | (pending) | hackertarget, crt, certspotter, dnsdumpster, commoncrawl, archiveorg, bgpview, ripe, robtex | 9 modules in one file `free_apis.go` |

**Total registered modules: 58** (dns_resolve + stor_db pre-existing, +56 new)

Batch 7 notes:
- Implementations are pragmatic: each module ports only the most useful single query path from the Python original. Netblock expansion, multi-page pagination, and DNS re-resolution are omitted for now.
- Added event types for archive.org: `INTERESTING_FILE_HISTORIC`, `URL_{PASSWORD,FORM,FLASH,STATIC,JAVA_APPLET,UPLOAD,JAVASCRIPT,WEB_FRAMEWORK}_HISTORIC`.
- `dnsdumpster` is best-effort: the Python module does a CSRF/POST dance that is brittle and often captcha-guarded. The Go port only scrapes the landing page for now.
- `certspotter` public API works without an API key for small queries; higher usage needs Basic auth (deferred to API-key batches).

Also added event type `BLACKLISTED_AFFILIATE_INTERNET_NAME` which was missing.

Batch 6 note: Python plan estimated "15" DNSBL modules, but only 6 pure DNSBL-pattern modules exist in Python SpiderFoot (spamhaus, sorbs, spamcop, uceprotect, dronebl, surbl). Other "blocklist" modules (blocklistde, abusech, voipbl, coinblocker, stevenblack_hosts, phishstats, etc.) download HTTP text lists rather than using DNSBL zones and will be ported in a later batch as an `httpBlocklist` pattern. `abusix` and `honeypot` are DNSBL but require an API key — deferred to the API-key batches.

## Remaining Batches (per original plan)

5. Public DNS Resolvers (10) — adguard, cloudflare, quad9, opendns, yandex, etc.
6. DNS/IP Blacklists (15) — spamhaus, sorbs, dronebl, etc. (shared DNSBL pattern)
7. Free APIs Part 1 (12) — hackertarget, certspotter, crt, dnsdumpster, commoncrawl, archiveorg, bgpview, ripe, robtex
8. Free APIs Part 2 (13) — googlesearch, bingsearch, duckduckgo, sublist3r, stackoverflow, searchcode
9. Phishing/Reputation (8) — phishtank, openphish, emergingthreats, threatcrowd
10. Social/Username (14) — social, accounts, github, twitter, flickr, keybase, gravatar
11. Email/Phone Services (14) — haveibeenpwned, hunter, clearbit, emailrep
12. Major APIs Part 1 (15) — shodan, virustotal, abuseipdb, censys, greynoise, ipinfo, securitytrails
13. Major APIs Part 2 (15) — riskiq, intelx, dehashed, leakix, threatfox, urlscan, xforce
14. Security/Threat Intel (14) — googlesafebrowsing, metadefender, hybrid_analysis, openbugbounty
15. Cloud/Crypto/Special (15) — s3bucket, azure, blockchain, etherscan, opencorporates
16. WHOIS-related + Hosting (10) — reversewhois, whoxy, networksdb, builtwith, whatcms
17. Tool Wrappers (13) — nmap, nuclei, dnstwist, wafw00f, whatweb (os/exec)
18. Misc Part 1 (16) — abstractapi, c99, googlemaps, pastebin
19. Misc Part 2 (16) — projectdiscovery, subdomain_takeover, wigle, zoneh

## Conventions Established (READ BEFORE CONTINUING)

### Module pattern
- One file per module, or group similar regex-based extractors into a shared
  file (see `content_extractors.go`, `content_misc.go`).
- Use generic `contentExtractor` base type for any module that:
  consume TARGET_WEB_CONTENT → run `func(string) []string` → emit one event type.
- Each module needs: `Meta()`, `Setup()`, `WatchedEvents()`, `ProducedEvents()`,
  `HandleEvent()`, `Finish()`. All exported types/methods need GoDoc comments.
- Register in `init()` via `module.Register("name", factory)`.

### Test pattern
- Test helpers in `content_extractors_test.go` (`runExtractor`, `makeContentEvent`)
  can be reused by all extractor tests in the same package.
- Use `module.Get(name)` (NOT `module.New` — does not exist) to fetch a registered
  factory in tests.
- Required tests per module: Meta, WatchedEvents, ProducedEvents, HandleNilEvent,
  Setup, plus at least one functional test.

### Build/test/lint commands (THIS ENVIRONMENT)
```bash
# Build (CGO disabled, GOTOOLCHAIN=local to avoid 1.25 download)
CGO_ENABLED=0 GOTOOLCHAIN=local go build ./...

# Test (vet disabled — vet segfaults in this environment)
CGO_ENABLED=0 GOTOOLCHAIN=local go test -vet=off -count=1 -timeout=120s ./...

# Format check (use this instead of `go vet`)
gofmt -l /workspaces/spiderfoot-Go/internal/
gofmt -w /workspaces/spiderfoot-Go/internal/   # to fix

# golangci-lint OOMs in this devcontainer — DO NOT use it. gofmt + tests is sufficient.
```

### Environment quirks (gotchas)
- `go vet` segfaults — always pass `-vet=off` to `go test`.
- `golangci-lint` OOMs (exit 137) — do not run it.
- `go mod tidy` will try to bump x/sys to 0.42+ which requires Go 1.25; this is OK
  because GOTOOLCHAIN=local stops it from auto-downloading. go.mod says `go 1.25.0`
  now — leave it alone.
- CGo errors with `gcc: -m64`. Always set `CGO_ENABLED=0`.

### Commit message format
```
feat: add Batch N modules — <category> (Phase 3)

Port N modules from Python SpiderFoot:
- module1: ...
- module2: ...

<any notes about shared helpers added>

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

## How to resume in a new session

1. Read `CLAUDE.md` for project overview.
2. Read this file to see what's done and what's next.
3. `git log --oneline feature/1-go-rewrite | head -10` to confirm last commit.
4. `ls internal/modules/` to see registered modules.
5. Pick the next batch from the table above and start implementing.
6. For each new module, look at the Python source under
   `/workspaces/spiderfoot-Go/modules/sfp_<name>.py` (full Python tree is in repo).
7. Use the Explore agent to read multiple Python sources in one shot rather than
   reading them individually — saves a lot of context.

## Open issues / decisions deferred

- **Zone transfer (dns_zonexfer)**: Current Go impl only does a TCP/53 reachability
  probe. Real AXFR needs `github.com/miekg/dns`. Add as a dependency when needed.
- **WHOIS server list**: Hardcoded ~20 TLDs in `whois_mod.go`. Falls back to
  `whois.iana.org` for unknown TLDs. May need a complete IANA list later.
- **API key management**: Modules in batches 11-15 need a config-driven API key
  system. Not designed yet. When starting Batch 11, design this first:
  - Likely add `opts["api_key"]` lookup in Setup
  - Document how `internal/config` exposes per-module options
- **Tool wrappers (Batch 17)**: Use `sflib.RunTool()` already in place. Modules
  must gracefully handle missing binaries (return nil from HandleEvent if
  `sflib.ToolAvailable()` returns false).
