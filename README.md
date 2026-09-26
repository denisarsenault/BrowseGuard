# BrowseGuard

A browser filter for iOS, macOS, and tvOS, built the way Apple's platforms
allow one to be built and shipped through the Mac App Store and the iOS App
Store. Feature-comparable to Malwarebytes Browser Guard: it blocks malware,
scams and phishing, ads, trackers, clickbait, in-browser cryptominers, and
unwanted-software portals, and it catches brand-new phishing domains with
heuristics rather than waiting for a blocklist to catch up.

Everything runs on device. Nothing about your browsing leaves the machine.

---

## What runs where

| | iOS / iPadOS | macOS | tvOS |
|---|---|---|---|
| Safari content blocker (ads, trackers, miners) | ✅ | ✅ | — |
| Safari web extension (real-time navigation checks, block page) | ✅ | ✅ | — |
| Heuristic phishing detection | ✅ | ✅ | — |
| Dashboard, category switches, allowlist | ✅ | ✅ | ✅ |
| iCloud sync of settings and allowlist | ✅ | ✅ | ✅ |

**tvOS has no web browser and no Safari extension point.** There is nothing on
an Apple TV to filter, and any app claiming otherwise is not filtering
anything. The tvOS target is therefore a genuine companion: it shows what the
household's other devices are blocking, and its category switches and allowlist
edits sync back to them over iCloud. If you would rather not ship a tvOS binary
at all, delete the `BrowseGuard-tvOS` target from `project.yml` — nothing else
depends on it.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ App Group container  group.com.mybrightzone.BrowseGuard      │
│   settings.json · allowlist.json · events.json               │
│   catalog.json  · blockerList.json (compiled Safari rules)   │
└───────▲──────────────────▲──────────────────────▲────────────┘
        │ read/write       │ read                 │ read + coordinated append
┌───────┴────────┐ ┌───────┴────────┐ ┌───────────┴─────────────┐
│ BrowseGuard    │ │ Content        │ │ Safari Web Extension    │
│ app (SwiftUI)  │ │ Blocker ext    │ │  background.js          │
│                │ │                │ │  content.js             │
│ ProtectionCoo- │ │ serves the     │ │  blocked.html           │
│ rdinator owns  │ │ compiled rule  │ │       ▲                 │
│ all mutation   │ │ file to WebKit │ │       │ native message  │
│                │ │                │ │ SafariWebExtensionHandler│
└────────────────┘ └────────────────┘ └─────────────────────────┘
```

Two filtering paths, deliberately:

1. **Content blocker — the fast path.** WebKit compiles our rules and evaluates
   them itself. Ad, tracker, and miner requests are stopped before they are
   made, with zero process wake-ups and no per-request code of ours running.
   This is where the bulk of the blocking happens.

2. **Web extension — the smart path.** Sees each top-level navigation and asks
   the native handler for a verdict. This is what makes malware and phishing
   blocks explainable: the user gets a block page telling them *why*, with a
   time-boxed "Continue anyway".

The JavaScript side never holds the blocklists, the heuristics, or the user's
settings. Those stay behind the App Group where native code can reach them and
a web page cannot. `ProtectionEngine` is one immutable, `Sendable` struct and
all three processes evaluate a host through it, so the verdict the app shows in
its UI is exactly the one the extension enforces.

### Your own block list

Separate from the threat feeds: a site you add here is blocked because you said
so, not because anything claims it is dangerous — and the block page says
exactly that rather than implying a threat. It is not a toggleable category,
because a switch that disables the list you built yourself would be confusing;
removing the entry is how you undo one.

Precedence is deliberate and enforced in two places that must agree:

1. Your block list
2. Your allowlist
3. Threat feeds
4. Heuristics

A block beats an allowlist entry, because deliberately blocking something you
once allowed should take effect without hunting down the old entry first —
adding a block also clears any allowlist entry for the same host. The compiled
Safari rules mirror this: user blocks are emitted *after* the allowlist's
`ignore-previous-rules`, so WebKit and the engine can never disagree about the
same host depending on how it was loaded. There is a test for that ordering.

This is also what makes a blocker test page like
`webbrowsertools.com/test-blocking-rules/` usable — those pages serve every
test resource from their own domain and expect you to add the rule yourself.
Nothing there is a threat, so no feed lists it, and none should.

### Heuristics

Blocklists are always behind. A phishing domain registered this morning is on
no list, but `app1e-icloud-verify.tk` is detectable from its shape alone.
`HeuristicScanner` scores a host on:

- Damerau-Levenshtein distance to protected brands (catches `gogole.com`)
- Brand name in a subdomain of an unrelated domain (`apple.com.secure.ru`)
- IDN homographs (`xn--`-encoded lookalikes)
- High-abuse TLDs, deep subdomain nesting, hyphen and digit stuffing
- Shannon entropy, to separate chosen names from generated ones
- Scam vocabulary (`verify`, `suspended`, `unlock`, …)

Signals accumulate. `Relaxed`/`Balanced`/`Strict` move the block and warn
thresholds. Every signal that fires is shown to the user on the block page in
plain language — no "trust us, it's bad".

---

## Getting it building

```bash
cd ~/Developer/BrowseGuard
xcodegen generate
open BrowseGuard.xcodeproj
```

`project.yml` is the source of truth. The `.xcodeproj` is generated and
git-ignored — change `project.yml` and regenerate, don't edit project settings
in Xcode and expect them to survive.

### Before it will actually run

1. **Set your Team.** In `project.yml`, fill in `DEVELOPMENT_TEAM` under
   `settings.base`, or set it once per target in Xcode's Signing &
   Capabilities tab.

2. **Register the App Group** `group.com.mybrightzone.BrowseGuard` in the
   Developer portal, and enable the App Groups capability on all five
   iOS/macOS targets.

   On macOS the App Store requires the Team ID prefix, so the macOS
   entitlements use `$(TeamIdentifierPrefix)group.com.mybrightzone.BrowseGuard`
   while iOS and tvOS use the bare form. `AppGroup.swift` reads the real value
   back out of the running code's own signed entitlements, so you do not have
   to hardcode your Team ID anywhere.

3. **Enable iCloud → Key-value storage** on the three app targets. All three
   share one store (`$(TeamIdentifierPrefix)com.mybrightzone.BrowseGuard`),
   which is what lets a change on the Mac reach the Apple TV.

4. **Change the bundle identifiers** if you are not `com.mybrightzone`. The
   three apps intentionally share one identifier so the App Store treats them
   as a Universal Purchase; the four extensions need distinct ones.

5. **tvOS brand assets.** The tvOS target ships without an app icon so it
   builds out of the box. Add the layered icon stack and top-shelf image in
   Xcode's asset editor before submitting.

### What you'll see before it's signed

Until the app is signed with a real team, Safari does not register the embedded
extensions, and every SafariServices call returns `SFErrorNoExtensionFound`
(`SFErrorDomain error 1`). That is the expected state, not a bug.

`reloadContentBlocker` reports this as `ReloadOutcome.extensionNotEnabled`
rather than as a failure, because it isn't one: the compiled rules are written
to the App Group *before* Safari is asked to reload, so they are already on
disk and correct, and Safari reads them the next time the extension loads. The
same is true of a reload Safari never acknowledges (`.notConfirmed`). Neither
sets a user-facing error — getting the extension switched on is what the setup
prompt is for. Expect a log line like:

```
Content blocker rules written (150); Safari has not registered the extension yet
```

State queries report "can't determine" rather than "off", and the app keeps
working on its bundled blocklists throughout. To watch the
`com.mybrightzone.BrowseGuard` subsystem:

```bash
/usr/bin/log show --last 5m --style compact --predicate 'subsystem == "com.mybrightzone.BrowseGuard"'
```

`ExtensionBridge` is defensive for two specific, verified reasons, both of
which crash an app that calls these APIs the obvious way:

- **`SFSafariExtensionManager` can raise an `NSException`.** It dispatches a
  private selector (`…sandboxExtensionToken:reply:`) to Safari's helper. On an
  unsigned or unsandboxed build there is no token to mint, the helper rejects
  the selector, and the resulting `NSInvalidArgumentException` cannot be caught
  from Swift. `BGExceptionBarrier` is a three-line Objective-C `@try/@catch`
  that turns it into a `nil` result.
- **Its completion handler is annotated `NS_SWIFT_UI_ACTOR`, but Safari does
  not honor that.** The reply arrives on the XPC connection's queue, so an
  inline Swift closure — compiled `@MainActor`, with a main-queue assertion in
  its prologue — dies with `SIGILL` before its first statement. The handler is
  therefore bound to an explicitly non-isolated type.

`SFContentBlockerManager` carries neither problem and is the correct API for
content-blocker state on macOS as well as iOS.

Both calls also run against a deadline, because a wedged Safari helper can
simply never invoke its completion handler. The two deadlines are deliberately
very different: a state lookup gets 5s, but a reload gets 60s, because a reload
hands WebKit up to 140,000 rules to recompile and a short deadline there would
report failure on a reload that was working fine.

### Turning it on after install

The app's own switch is only half of it — the user has to enable the extensions
on the Safari side, and the app detects and prompts when they have not:

- **macOS:** Safari › Settings › Extensions, tick BrowseGuard and BrowseGuard
  Blocker. The app has an "Open Safari Settings" button that takes you there.
- **iOS:** Settings app › Safari › Extensions, turn both on, then set
  BrowseGuard's permissions to Allow on All Websites.

---

## Blocklists

`Shared/Resources/Blocklists/*.json` ships a baseline so the app protects
people offline, on first launch, before any network call. `scripts/build_feeds.py`
generates it from upstream sources and also emits the hosted update feed.

| Feed | Source | Licence | Entries | Freshness |
| --- | --- | --- | --- | --- |
| malware | [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter) (abuse.ch) | MIT | ~1.9k | every 12h |
| scam | [phishing-filter](https://gitlab.com/malware-filter/phishing-filter) (OpenPhish, IPThreat, PhishTank) | MIT | ~40k | every 12h |
| cryptojacking | [adblock-nocoin-list](https://github.com/hoshsadiq/adblock-nocoin-list) | MIT | ~300 | **snapshot** |
| pup | [pup-filter](https://gitlab.com/malware-filter/pup-filter) | MIT | ~190 | **snapshot** |
| advertising, tracking, clickbait | hand-curated baseline | — | ~110 | manual |

Every source is permissively licensed and safe to redistribute in a paid App
Store app. Two deliberate exclusions: **DuckDuckGo Tracker Radar** is
CC BY-NC-SA (non-commercial — needs a licence from DDG), and **Google Safe
Browsing's** free tier is non-commercial only; its commercial equivalent is the
paid Web Risk API. Safari already ships Google's fraudulent-site warnings, so
Web Risk buys you less than its price suggests.

### The two snapshots

`pup` and `cryptojacking` are marked `snapshot: true` because **their upstreams
have stopped updating** — pup-filter paused daily builds in May 2023, and the
nocoin list was last touched in March 2025. The data is still valid as far as
it goes, but it is frozen, and the builder says so on every run rather than
letting a dead feed pass as live. Cryptominer kits turn over slowly enough that
this is tolerable; a stale *phishing* feed would not be, which is why that one
fails the build if it goes more than 7 days without an upstream change.

If you want live PUP coverage you will need a different source or a commercial
feed. Nothing in the pipeline pretends otherwise.

### Ads and trackers

Still the small hand-curated baseline. The mainstream lists — EasyList,
EasyPrivacy, AdGuard, uBlock's own — are **GPL3**, though EasyList is dual
licensed and its CC BY-SA 3.0 arm is the usual route for a closed-source app:
share-alike binds the list you redistribute, not your code, because the list is
data you fetch rather than linked code. Attribution to "The EasyList authors"
is required. Converting adblock syntax (element hiding, `$` options,
exceptions) to Safari's declarative format is a real piece of work and is not
done here. Get a lawyer's read before shipping EasyList-derived rules.

### Running it

```bash
python3 scripts/build_feeds.py --check-only                    # validate, write nothing
python3 scripts/build_feeds.py --base-url https://you.github.io/BrowseGuard
python3 scripts/build_feeds.py --update-bundled --base-url ... # refresh the baseline
python3 scripts/test_build_feeds.py                            # 22 tests, no network
```

`.github/workflows/blocklists.yml` runs this twice daily and publishes `dist/`
to GitHub Pages. It deliberately **does not** touch the bundled baseline —
that is what a fresh install has before its first network call, so refreshing
it is a release decision, not something a cron job should do behind your back.

Point the app at the published feed by setting `BROWSEGUARD_FEED_URL` in
`project.yml` to your Pages URL. It must be HTTPS; the app rejects anything
else, because a blocklist fetched over plaintext is an instruction set an
attacker on the path can rewrite.

### What the builder refuses to publish

A pipeline that ships whatever it downloaded is how a security app ends up
blocking apple.com. Every feed must clear:

- **A floor** — fewer entries than the minimum means a mirror served an error
  page with a 200.
- **A shrink limit** — losing more than half the entries is a broken upstream,
  not good news.
- **A guard list** — a few protected domains (apple.com, icloud.com,
  cloudflare.com, …) are dropped with a warning, since big aggregated feeds do
  occasionally scoop up a CDN subdomain. *Many* of them rejects the feed whole,
  because that is what poisoning looks like. This fires in practice: the
  phishing feed currently lists a `gstatic.com` metrics subdomain.
- **A freshness check** — stale data is rejected unless the feed is explicitly
  a snapshot.

### Applying rules

Compiling the catalog is about a second of CPU and several megabytes of JSON,
so two things are deliberate in `ProtectionCoordinator`:

- **It runs off the main actor.** On the main actor it froze the window on
  every category toggle.
- **It is coalesced.** `CoalescingRunner` collapses a burst of toggles into one
  compile, and serializes runs so an older compile can never finish last and
  overwrite newer rules. Launch and finished blocklist updates bypass the
  delay via `runNow`.

The rule count is published as soon as the compile finishes, not when Safari
acknowledges — the rules are live in the App Group the moment they are written,
and WebKit's reload can take many seconds on a full catalog. Showing "0 rules
active" during that window reads as "you are not protected" when the opposite
is true.

Feeds are merged by `identifier`, highest `version` wins, and a version bundled
in an app update beats a stale download. Versions only bump when content
actually changes, so devices do not re-download identical feeds. WebKit caps a
content blocker at 150,000 rules and rejects the whole list past that; the
compiler budgets to 140,000 and drops the least severe entries first. The
current catalog compiles to about 42,400.

## Platform gotchas

Four things here look like bugs in this project but are Apple-platform
behaviour. All four cost real debugging time; none is guessable from the docs.

### `ENABLE_DEBUG_DYLIB` silently breaks app extensions

Xcode 16+ splits a target's code into a separate `.debug.dylib` and leaves a
launcher stub as the main binary. Fine for an app you run; fatal for an app
extension. The host launches the appex, `NSExtensionPrincipalClass` cannot be
resolved because the stub contains none of your classes, and **Safari hangs
forever waiting for an extension that never starts** — which surfaces as a
`reloadContentBlocker` call that never returns, with no extension process in
the log at all.

The tell is the binary itself: 38 KB, zero Swift symbols, and the principal
class name absent even from `strings`. All four extension targets therefore set
`ENABLE_DEBUG_DYLIB: NO`.

### `reloadContentBlocker` never calls back on macOS

`SFContentBlockerManager.getStateOfContentBlocker` answers for the same
identifier in ~70 ms and reports the blocker enabled. `reloadContentBlocker`'s
completion handler, for that same identifier, never fires at all. The reload is
applied; it is just never acknowledged. So macOS gets a 5 s deadline and a
`.notConfirmed` outcome, and iOS — where the API does report back, and where a
large rule set legitimately takes WebKit tens of seconds — gets 60 s. Waiting a
minute for an answer that is not coming only strands the UI after every toggle.

### The content blocker extension has a tiny memory budget

Much smaller than the app's. Two consequences:

- It compiles a **minimal** source set — `AppGroup` and the request handler,
  nothing else. It resolves a path and hands Safari a file URL; it never
  evaluates a host, so none of the engine belongs in it. Including the engine
  took the binary from 141 KB to 881 KB and got the process killed for memory
  pressure on an iPhone.
- The handler refuses a shared rule file over 2 MB and serves the bundled
  baseline instead. An oversized list gets the extension killed, after which
  there is *no* blocking at all — degraded beats fatal for a security app.
  Only the app rewrites that file, so a stale oversized one survives until the
  app runs again.

### `containerURL` is an XPC call, not a property read

`containerURL(forSecurityApplicationGroupIdentifier:)` round-trips to
`containermanagerd` on every call. As a computed property it was being paid on
every file read, every write and every stat — and the web extension touches it
five or more times per navigation. It is a `static let` now: a process's
container assignment cannot change while it runs. This took the test suite from
169 s to 12 s.

Related: `ProtectionEngine.current()` runs once per navigation, and used to
re-decode the 2.4 MB catalog and rebuild a 42,000-entry index each time —
about 20 MB of allocation per page load. `SharedStore.catalog()` now caches the
decoded catalog, invalidated by file modification date. The test for it counts
decodes rather than timing them, because a timing assertion on a loaded machine
cannot tell "the cache worked" from "the machine was fast" — the same test
measured 29 s, 106 s and 267 s on three consecutive runs.

## Testing

```bash
xcodebuild test -project BrowseGuard.xcodeproj -scheme BrowseGuard-macOS -destination 'platform=macOS'
```

The test target compiles the engine sources directly — no host app, no Safari —
so matching, heuristics, and rule compilation are exercised headlessly. The
suite covers host canonicalization, suffix matching (including the
`notdoubleclick.net` near-miss), heuristic true and false positives, the
allowlist beating a malware listing, bypass expiry, rule-limit truncation, and
that a compiled `url-filter` anchors at the host rather than matching a query
string.

---

## App Store notes

- Every target is sandboxed; nothing needs a privileged helper, a kernel
  extension, or a network extension.
- Deliberately **not** using `NEFilterDataProvider` or `NEDNSProxyProvider`.
  Both require a supervised/MDM-managed device on iOS and neither is
  distributable through the App Store for a consumer utility.
- The activity log records hosts only — never full URLs, query strings, or page
  titles. That is a privacy decision first and a log-size decision second.
- iCloud sync carries settings, the allowlist, and rolled-up counters. The
  event log stays on device; `NSUbiquitousKeyValueStore` caps at 1 MB and a
  browsing log does not belong in the cloud regardless.
- `ITSAppUsesNonExemptEncryption` is declared `false` on all three apps.

---

## Layout

```
Shared/
  Core/       ThreatCategory, Blocklist, DomainMatcher, HeuristicScanner,
              Verdict, ProtectionEngine, ContentRuleCompiler, AppGroup,
              ExtensionBridge
  Storage/    ProtectionSettings, Allowlist, BlockEvent, SharedStore,
              AllowlistStore, EventLogStore
  Sync/       CloudSync
  Updates/    BlocklistUpdater
  ViewModels/ ProtectionCoordinator
  Views/      shared SwiftUI leaves used by all three platforms
  Resources/  bundled baseline blocklists
iOS/ macOS/ tvOS/     per-platform app targets
ContentBlocker/       request handler, shared by both platform extensions
WebExtension/         native handler + manifest, background.js, content.js,
                      block page, popup
Tests/                engine tests (Swift Testing)
```
