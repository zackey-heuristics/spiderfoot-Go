# Phase 3: Python → Go Module Port — Progress & Handoff

This file tracks progress on porting all 234 Python SpiderFoot modules to Go.
It is intended as a handoff document so a fresh Claude Code session can resume
without replaying the original planning conversation.

## Session handoff (last updated 2026-04-09)

**Branch**: `feature/1-go-rewrite` — Batch 16 committed locally.
**Last commit**: Batch 16 — More Free Reputation Feeds.
**Registered modules**: 113 / 234.
**Next batch**: **Batch 17** — to be selected from remaining Python modules. Follow the plan-implement-test-review-commit cycle established in Batches 11-14.

**Batch 14 Codex adversarial review**: Ran against the full working tree. All 3 findings were against pre-existing untracked files (`.devcontainer/`, `.claude/settings.json`) that are explicitly out-of-scope and NOT part of the Batch 14 commit. The Batch 14 files (`security_intel.go`, `security_intel_test.go`) passed adversarial review with zero findings.

**To resume in a fresh session**, paste this prompt:

> SpiderFoot-Go の Phase 3 Module Port を続けます。現在 99/234 モジュール完了、branch は `feature/1-go-rewrite`、最終コミットは `658b5752`。`.claude/plans/phase3-module-port-progress.md` と `CLAUDE.md` を読んで現状を把握してから、次の Batch 15 を選定・実装してください。Batches 11-14 で確立した規約 (vendor-prefixed opt keys、no generic `api_key` fallback、`seen.begin` に `evt.Type+":"+evt.Data` を渡す、JSON parse 成功後に `committed=true`、`url.PathEscape`/`url.QueryEscape`、env-var 制約のため module 名は single-word) を踏襲してください。

**Known pre-existing untracked files** (DO NOT commit as part of any batch):
- `.devcontainer/` — separate concern, has security issues flagged by Codex, needs its own PR
- `core`, `internal/db/core` — crash dump artifacts, should be gitignored in a separate cleanup commit
- `internal/modules/dnsbl_test.go` has a pre-existing `gofmt` violation — fix in a separate cleanup commit

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
| 7 — Free APIs Part 1 | `248504c9` | hackertarget, crt, certspotter, dnsdumpster, commoncrawl, archiveorg, bgpview, ripe, robtex | 9 modules in one file `free_apis.go` |
| 8 — Free APIs Part 2 | `c2a0d88e` | googlesearch, bingsearch, duckduckgo, sublist3r, stackoverflow, searchcode | 6 modules in `search_apis.go` |
| 9 — Phishing/Reputation | `c2a0d88e` | phishtank, openphish, emergingthreats, threatcrowd, phishstats | 5 modules in `phishing_reputation.go` (shared `hostFeed`/`ipFeed` patterns) |
| 10 — Social/Username | `c2a0d88e` | social, accounts, github, twitter, flickr, keybase, gravatar, slideshare | 8 modules in `social_modules.go` |
| — Dedup audit (all batches) | `81294a87` + `cd131938` | — | Unified atomic reserve/release via shared `seenSet.begin` primitive; see "Shared dedup primitive" section below |
| 11 — Email/Phone Services | `327e6b4b` | haveibeenpwned, hunter, clearbit, emailrep | 4 modules in `email_services.go`; first batch requiring API keys — establishes the API key convention documented below |
| 12 — Major APIs Part 1 | `ac620c8f` | shodan, virustotal, abuseipdb, censys, greynoise, ipinfo, securitytrails | 7 modules in `major_apis.go`; exercises 4 distinct auth schemes (query, header, Basic, Bearer); censys uses uid+secret pair |
| 13 — Major APIs Part 2 | `8dfc9a9a` | riskiq, intelx, dehashed, leakix, threatfox, urlscan, xforce | 7 modules in `major_apis2.go`; introduces `majorAPIFetchPOST`/`basicAuthHeader` shared helpers. threatfox+urlscan are free (no API key), rest use vendor-prefixed keys; multi-credential modules (riskiq/dehashed/xforce) use two opt keys each |
| — Dedup key + commit ordering fix | `d380caf6` | — | Codex adversarial review of Batch 13 flagged two high-severity issues applying across Batches 7-13. (1) `seenSet.begin` key composed as `string(evt.Type)+":"+evt.Data` so IP_ADDRESS vs AFFILIATE_IPADDR (and DOMAIN_NAME vs INTERNET_NAME) no longer collide and drop findings. (2) `committed = true` moved to after `json.Unmarshal` success, so an HTTP 200 with garbage JSON no longer permanently suppresses retries. HIBP retains 404-definitive semantics. Text-based parsers (AbuseIPDB/hostFeed/ipFeed) unchanged. |
| 14 — Security/Threat Intel | `658b5752` | googlesafebrowsing, metadefender, hybridanalysis, openbugbounty | 4 modules in `security_intel.go`. `openbugbounty` is free (HTML scrape via regex). `hybrid_analysis` renamed to `hybridanalysis` (single-word) to satisfy the `SF_MODULE_<MOD>_<KEY>` split-on-first-underscore rule. Adds local `postHybridForm` helper for `application/x-www-form-urlencoded` POSTs since `majorAPIFetchPOST` forces JSON. Adversarial review: zero findings against Batch 14 files. |
| 15 — Free Threat Feeds + Blockchain | (local) | abusechfeodo, abusechssl, abusechurlhaus, botvrij, cinsscore, blocklistde, coinblocker, blockchain | 8 modules in `threat_feeds.go`. Seven reuse `hostFeed`/`ipFeed` generics from `phishing_reputation.go`; only `blockchain` (per-event blockchain.info wallet-balance JSON lookup for `BITCOIN_ADDRESS`) is custom. The `abuse_ch` Python module is split into three single-word Go modules so each feed has its own cache lifecycle and satisfies the env-var single-underscore rule. URLhaus parser is a fast-path host extractor mirroring Python's `split('/')` shortcut. |
| 16 — More Free Reputation Feeds | (local) | talosintel, alienvaultiprep, greensnow, vxvault, stevenblack, multiproxy | 6 modules in `threat_feeds2.go`. All reuse `ipFeed`/`hostFeed` generics. Adds an optional `parser` field to `ipFeed` so feeds with non-plain-IP line formats (alienvaultiprep `IP #desc`, multiproxy `IP:port`) can override `parseIPList` without copying the HandleEvent machinery. vxvault extracts hosts from URL lines; stevenblack parses hosts-file format skipping `localhost` aliases. |

**Total registered modules: 113** (dns_resolve + stor_db pre-existing, +103 new)

## API Key Convention (established in Batch 11)

Modules that require third-party API keys follow this convention:

1. **Opts key name**: Python-compatible per-module prefix to avoid
   collisions with the `default:` YAML section that `ModuleOpts` merges.
   Examples: `hibp_api_key`, `hunter_api_key`, `clearbit_api_key`,
   `emailrep_api_key`. For modules with multiple credentials, use the
   same convention (`google_api_key` + `google_cse_id`).

2. **Env var injection**: `SF_MODULE_<MODNAME>_<KEY>=<value>` is read
   by `config.applyModuleEnvOverrides` (in `internal/config/config.go`)
   and written to `cfg.Modules[mod][key]`. Module/key split is on the
   first underscore after the `SF_MODULE_` prefix, so module names
   must be single-word (all current SpiderFoot-Go names satisfy this).

   **Modules read ONLY the vendor-prefixed key name** (e.g.
   `hibp_api_key`), never a generic `api_key`. This is a hard
   security boundary: a `default: api_key: xxx` YAML stanza would
   otherwise leak that key to every module that consumes `api_key`,
   silently shipping it to unrelated upstream vendors. Codex
   adversarial review (2026-04-08) flagged a fallback-on-`api_key`
   implementation as a credential leakage regression and it was
   reverted. Regression test:
   `TestEmailServicesRejectGenericAPIKey` in
   `internal/modules/email_services_test.go`.

   Consequence: env-var users must use the doubled form to set a
   per-module key, e.g. `SF_MODULE_HIBP_HIBP_API_KEY=xxx`. The first
   `HIBP` segment selects the module bucket; the second `HIBP_API_KEY`
   is the literal opt key the module reads. Awkward but explicit and
   safe. A future enhancement could add a config-side translation
   layer that maps `SF_MODULE_HIBP_API_KEY` → `hibp_api_key` only when
   it does not collide with an existing vendor-namespaced key, but
   that work is deferred until the trust-boundary semantics are
   formalized.

3. **`module.Meta.RequiresAPIKey bool`**: new field on the Meta struct
   (`internal/module/meta.go`). Modules set this to `true` when they
   no-op without a key. Zero-value is `false`, preserving existing 77
   modules untouched. Future web UI work can surface a "missing key"
   indicator based on this flag.

4. **Runtime behavior**: `Setup` reads the key via `optString(opts,
   "<mod>_api_key", "")` and stores it. `HandleEvent` begins with
   `seenSet.begin` (so dedup still applies), then returns `nil, nil`
   if the key is empty. Key-missing events do NOT commit the seenSet
   reservation, so a later scan with the key populated will retry.

## Shared dedup primitive (MUST READ before adding a new module)

All HTTP-backed and DNS-backed HandleEvents in Batch 1-10 use a single
shared primitive, `seenSet.begin`, defined in
`internal/modules/free_apis.go`. This was introduced after a 10-round
Codex adversarial review iteration addressed: silent false-negatives
on transient failure, TOCTOU races between contains-then-act, waiter
semantics vs worker starvation, context cancellation on waiters, and
generation safety across scan teardown.

Final design: **non-blocking skip-on-in-flight with deferred finish**.

```go
func (m *MyModule) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
    if evt == nil || evt.Data == "" {
        return nil, nil
    }
    skip, finish, err := m.seen.begin(ctx, evt.Data)
    if err != nil {
        return nil, err
    }
    if skip {
        return nil, nil
    }
    committed := false
    defer func() { finish(committed) }()

    // ... do network work ...
    resp, err := client.FetchURL(ctx, url)
    if err != nil || resp.StatusCode != 200 {
        return nil, nil // defer releases reservation → later event can retry
    }
    // Upstream responded definitively — commit the reservation.
    committed = true
    // ... parse, emit events ...
    return results, nil
}
```

Key invariants:
- `committed` MUST be set to `true` only after a definitive upstream
  response (HTTP 200, definitive DNS NXDOMAIN, etc.). Transient
  failures (network error, non-200, SERVFAIL) fall through to the
  deferred `finish(false)` which releases the reservation so a later
  event can retry.
- The `ctx` parameter is accepted by `begin` for API symmetry but is
  not read by the current implementation — the primitive is
  deliberately non-blocking (skip-on-in-flight) to avoid stalling
  scan workers behind slow upstream I/O.
- `finish` applies a pointer-equality generation guard: if
  `clear()` wiped the map or a later scan reserved the same key, the
  stale handler's mutation is skipped so a successor scan's state is
  never corrupted.
- DNS modules (`ipDNSBL`, `publicDNSResolver`) also use `seenSet`
  directly — do NOT reintroduce per-struct raw maps with local
  `markSeen`/`releaseSeen` helpers.
- Pure-regex modules (e.g. `Social`, `content_extractors.go`) can
  call `finish(true)` unconditionally at the end of HandleEvent since
  there is no network failure to distinguish.

Regression tests for this primitive live in
`internal/modules/phishing_reputation_test.go`:
- `TestSeenSetSkipOnInFlight` — non-blocking dedup
- `TestSeenSetFinishAfterClearIsSafe` — generation guard
- `TestHostFeedConcurrentDedup` — 10 concurrent callers → 1 emission
- `TestHostFeedRetryAfterTransientFailure` — sequential retry after transient
- `TestFetchOnceRetriesOnFailure` / `TestFetchOnceCachesSuccess` — fetchOnce helper

Known tradeoff (explicitly accepted after rounds 6-8):
A concurrent duplicate arriving while an owner is mid-fetch does NOT
re-run the fetch if the owner then fails transiently. Sequential
retry via a later event remains correct. This tradeoff favors scan
liveness over enrichment completeness in the rare concurrent-duplicate
case.

Batch 10 notes:
- `social` is regex-only on `LINKED_URL_EXTERNAL`; emits `SOCIAL_MEDIA` (`"<service>: <url>"`) plus `USERNAME`. 9 platforms covered (LinkedIn, GitHub, Bitbucket, GitLab, Facebook, YouTube, Twitter, SlideShare, Instagram).
- `accounts` is **pragmatic**: lazy-fetches the WhatsMyName JSON once, then sequentially probes the **first 50** sites per username (`accountsMaxSites`). Python uses 20 worker threads with no cap — promote to a worker pool when scan throughput matters.
- `twitter` and `slideshare` rely on legacy HTML scraping; the upstream pages are likely broken/changed since the Python module was written. Best-effort.
- `flickr` extracts the `site_key` from the public homepage at runtime (same as Python); a single search-page query is performed (no pagination).
- `keybase` parses `proofs_summary.all`, `cryptocurrency_addresses.bitcoin`, and the primary PGP bundle.
- `gravatar` requires `crypto/md5` for the email hash. No `EMAILADDR_GENERIC`/IM expansion (deferred).
- **NOTE for future test authors**: `event.New` requires a non-nil source for non-ROOT events. Construct a `event.ROOT` event first (see `TestSocialExtractor`).

Batch 9 notes:
- Introduces two shared generics: `hostFeed` (URL→hostname blocklists like phishtank/openphish) and `ipFeed` (IP blocklists like emergingthreats). Both lazily fetch the feed via a `fetchOnce` helper and reset on `Finish()` so each scan re-downloads.
- Netblock CIDR expansion is **not** performed for `NETBLOCK_MEMBER`/`NETBLOCK_OWNER` events — only direct IP membership is checked. Promote to a CIDR walker when needed.
- threatcrowd is implemented best-effort; the upstream service has been intermittently offline since 2022, so callers should not rely on it.
- phishstats hits the `_where=(ip,eq,X)&_size=1` filter form. Only matches when the API echoes the exact IP back.

Batch 8 notes:
- googlesearch / bingsearch require API credentials via opts (`google_api_key`+`google_cse_id`, `bing_api_key`). Without keys they no-op gracefully — full API-key config wiring is still deferred to batches 11-15.
- bingsearch uses `net/http` directly because `sflib.HTTPClient` does not yet expose custom request headers (Bing requires `Ocp-Apim-Subscription-Key`). Consider extending HTTPClient with a `Headers` option later.
- duckduckgo only emits `DESCRIPTION_ABSTRACT` / `DESCRIPTION_CATEGORY` (no AFFILIATE_DESCRIPTION_* event types exist yet — Python-only). Affiliate handling deferred.
- stackoverflow ports the `/search/excerpts` query and harvests emails via `sflib.ExtractEmails`. The Python module's secondary `/questions/{id}` IP/username extraction is omitted.
- searchcode fetches only the first results page (p=0, per_page=20). Python module paginates up to 10 pages.

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
