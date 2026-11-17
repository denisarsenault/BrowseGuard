# BrowseGuard

A browser filter for iOS, macOS, and tvOS, built the way Apple's platforms
allow one to be built and shipped through the Mac App Store and the iOS App
Store. Feature-comparable to Malwarebytes Browser Guard: it blocks malware,
scams and phishing, ads, trackers, clickbait, in-browser cryptominers, and
unwanted-software portals, and it catches brand-new phishing domains with
heuristics rather than waiting for a blocklist to catch up.

Everything runs on device. Nothing about your browsing leaves the machine. The
only network traffic is blocklist downloads, and StoreKit's subscription checks
with Apple.

BrowseGuard is a paid app. Access is an auto-renewing subscription; see
[Subscription](#subscription).

---

## Features

**Protection**

- Seven switchable categories: malware, scams and phishing, ads, trackers,
  clickbait, cryptojacking, and unwanted programs.
- Your own **block list**, separate from the threat feeds. Blocks say so
  plainly rather than claiming the site is dangerous.
- An **allowlist**. Sites you allow stay allowed, and a block on the same site
  removes the allowance.
- **Heuristic phishing detection** at three sensitivities: Relaxed, Balanced
  and Strict. Each block page lists the signals that fired.
- **Continue anyway** on a block page. It lets you past for one hour by default,
  recorded as a temporary allowlist entry that lapses on its own. The allowlist
  editor shows when it runs out.
- **Blocklist updates**, automatic or on demand, from the macOS menu bar
  (Check for Blocklist Updates).

**Tools**

- **Check a site.** Paste a link to get BrowseGuard's verdict without loading the
  page (iOS and macOS).
- **Activity log.** Records hosts only, never full URLs, query strings or page
  titles. It can be turned off.
- **iCloud sync** of settings, the allowlist and the block list, behind a toggle.
- **Chrome popup.** Shows the verdict for the current site, and lets you block or
  always allow it.
- **Duplicate-install detection** on macOS, with a one-click path to move stray
  copies to the Trash. See [One copy only](#one-copy-only).

**Where each lives**

- **iOS and iPadOS:** Protection, Activity, Sites and Settings tabs.
- **macOS:** a main window (Overview, Activity, Sites, What to Block) and a
  Settings window with heuristic sensitivity, the activity log, iCloud sync, the
  block page, automatic updates and the blocklist catalog.
- **tvOS:** Overview, Activity, What to Block, Allowed Sites and Blocked Sites,
  mirroring the devices you use BrowseGuard on.

---

## What runs where

| | iOS / iPadOS | macOS | tvOS | Chrome |
|---|---|---|---|---|
| Network-level blocking (ads, trackers, miners) | ✅ | ✅ | — | ✅ |
| Real-time navigation checks, block page | ✅ | ✅ | — | ✅ |
| Heuristic phishing detection | ✅ | ✅ | — | ✅ |
| Dashboard, category switches, allowlist | ✅ | ✅ | ✅ | popup only |
| iCloud sync of settings and allowlist | ✅ | ✅ | ✅ | — |

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
│   settings.json · allowlist.json · userBlocklist.json        │
│   entitlement.json · events.json · catalog.json             │
│   blockerList.json (compiled Safari rules)                  │
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

### Settings migration

`ProtectionSettings` carries a `schemaVersion`, and `categoryIntroducedIn`
records the schema each `ThreatCategory` first shipped in. On decode, any
category newer than the version a file was written with is switched **on**.

This exists to tell two situations apart that otherwise look identical — an
absent category because the user switched it off, and an absent category
because it did not exist when they last saved. Without the version, every new
protection would arrive silently disabled for existing users, which is the
worst possible default for a security feature. A category absent from a file
written at the *current* schema is a deliberate choice and is left alone.

**When you add a case to `ThreatCategory`:** add it to `categoryIntroducedIn`
and bump `currentSchemaVersion`. A test fails if you forget.

Categories are decoded as raw strings and unknown ones are skipped, so a file
written by a newer build — or one naming a category since removed — loses that
entry rather than failing the whole read and resetting every other preference.

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

## Subscription

Access is sold as an auto-renewing StoreKit 2 subscription, in two plans inside
one subscription group. A subscriber can move between plans without being billed
twice.

| Product ID | Period | Price in the local StoreKit file |
| --- | --- | --- |
| `com.mybrightzone.BrowseGuard.monthly` | 1 month | $2.99 (placeholder) |
| `com.mybrightzone.BrowseGuard.annual` | 1 year | $19.99 (placeholder) |

The prices in `StoreKit/BrowseGuard.storekit` are placeholders for local testing.
Real prices are set in App Store Connect. The product IDs there must match these
exactly. A mismatch shows up as "no products" on the paywall.

### What happens without a subscription

Until StoreKit reports an active subscription, the app shows a paywall in place of
its interface, through `SubscriptionGate`. On macOS this covers both the main
window and the Settings window. The paywall offers both plans and a Restore
Purchases button, with the renewal and cancellation terms and links to Terms,
Privacy and Manage Subscriptions. The Manage Subscriptions link is not on tvOS.

Lapse is enforced in the protection path, not just in the UI:

- **Engine.** `ProtectionEngine.effective(...)` turns protection off whenever the
  entitlement is not active. The Safari web extension's verdicts go through the
  engine, so they stop too.
- **Content blocker.** When the entitlement is inactive,
  `ContentBlockerRequestHandler` serves `noRules.json`, a rule list that blocks
  nothing. It makes that decision by reading the date from the App Group itself,
  so it works while the app is closed.
- **Your settings are kept.** A lapse does not erase your choices. Resubscribing
  puts protection back the way you left it.

### How the entitlement is stored

`SubscriptionStore` asks StoreKit for the newest verified, unrevoked transaction
in the group. It writes an `EntitlementRecord` (product, expiry, grace end) to
`entitlement.json` in the App Group. The extensions cannot call StoreKit, so they
read that file.

Readers compare its dates with the clock. They do not trust a stored "active"
flag. A subscription that lapses while the app is closed therefore stops working
without anything having to run to notice.

The app refreshes the record at launch, whenever it becomes active, and when the
paid period or the grace window ends. If Apple is retrying a failed renewal, the
grace period keeps protection on until it runs out.

### Why StoreKit and not a license key

App Store Review Guideline 3.1.1 requires digital features to be sold through
in-app purchase. The App Store is the authority, and the record is only a cache of
what StoreKit reported.

Known limit: `entitlement.json` is an ordinary file in the App Group container, so
anyone who can edit that container can change it. This is accepted for v1.
Verifying the signed transaction inside the extension would close the gap if it
matters later.

### Not covered by the subscription

The Chrome extension is **not** gated. It carries its own lists and nothing syncs
from the Apple apps, so the subscription does not reach it. Whether it belongs in
the paid offer has not been decided.

### Before release

1. Create the two products in App Store Connect with the IDs above, in one
   subscription group.
2. Set `BROWSEGUARD_TERMS_URL` and `BROWSEGUARD_PRIVACY_URL` in `project.yml`. Left
   empty, the paywall's links are missing.
3. Test in Xcode with `StoreKit/BrowseGuard.storekit`, then in the sandbox: a
   purchase, a renewal, Restore Purchases, and a lapse.

---

## One copy only

BrowseGuard is meant to run as a single copy, and the code enforces that in two
places.

**Inside the app (macOS).** A second launch hands focus to the copy already
running and quits. Two copies would both write the App Group state, and the stale
one would overwrite the other's settings.

**Duplicate detection (macOS).** Safari registers a Safari extension for every
copy of the app that Launch Services knows about. So an old build in
`~/Downloads`, a duplicate in `~/Applications`, or a drag-installed update beside
the original shows up as two extensions in Safari, and the stale one can serve old
rules. The app lists the copies it finds and shows a banner when there is more
than one:

- **Reveal** shows the copy in Finder.
- **Move to Trash** opens a panel pointed at that copy. Selecting it is the
  confirmation, which the sandbox requires before the app may touch the bundle.
- The prompt appears once per app version. Someone who keeps both copies is not
  nagged on every launch, but an update, which is when an old copy goes stale,
  gets one reminder.

**Checking from the terminal.** `scripts/single-copy.sh` reports the installed
copies, the running processes and the Safari registrations. It passes only when
there is one copy, in `/Applications`, one process, and both extensions registered
from that copy. Xcode registers every build product with Launch Services, so each
build can add another copy. Run the script after building.

```bash
./scripts/single-copy.sh          # report only
./scripts/single-copy.sh --fix    # quit extra copies, unregister them, move them to the Trash
```

`--fix` reports failure if a copy could not be trashed. Allow your terminal to
control Finder (System Settings › Privacy & Security › Automation), or move the
copy by hand. Afterwards, quit and reopen Safari and run the script again.

---

## Uninstalling

`scripts/uninstall.sh` removes BrowseGuard, its Safari extensions and their data.
Run with no arguments, it only reports what it would remove.

```bash
./scripts/uninstall.sh                 # report only
./scripts/uninstall.sh --yes           # move everything to the Trash
./scripts/uninstall.sh --yes --delete  # remove permanently
```

It quits BrowseGuard, turns off and unregisters the Safari extensions, then removes
the app, the per-app containers, preferences, caches, and the App Group container.
Trashing goes through Finder, so the terminal needs permission to control Finder
(see above), or use `--delete`.

It deliberately leaves these alone:

- **Safari's own settings.** The extensions disappear with the app. Editing Safari's
  preferences to force that would risk your other extensions.
- **Your subscription.** Removing the app does not cancel it. Cancel in Settings ›
  Apple Account › Subscriptions, or in the App Store on a Mac.
- **The Chrome extension.** Remove it at `chrome://extensions`.
- **iCloud data.** If sync was on, your settings and lists come back on reinstall.
  Turn sync off in the app first to remove them for good.

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
   Developer portal, and enable the App Groups capability on every app and
   extension target.

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

6. **StoreKit for local testing.** The app schemes run with
   `StoreKit/BrowseGuard.storekit`, so the paywall works in Xcode without App Store
   Connect. Create the same products in App Store Connect before release (see
   [Subscription](#subscription)).

7. **Store and legal links.** Set `BROWSEGUARD_TERMS_URL` and
   `BROWSEGUARD_PRIVACY_URL` in `project.yml`. Set `BROWSEGUARD_CHROME_URL` once the
   Chrome extension is listed in the Web Store.

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

---

## Chrome

`scripts/build_chrome.sh` assembles a Manifest V3 extension into `dist/chrome`,
loadable unpacked from `chrome://extensions`. Edge works from the same bundle;
Firefox is close, with some declarativeNetRequest differences.

### One codebase, two adapters

`WebExtension/Shared/` holds everything browser-agnostic — the service-worker
orchestration, the block page, the popup, the content script. Only two files
differ per browser:

| | Safari | Chrome |
|---|---|---|
| `manifest.json` | Safari web extension | MV3 + declarativeNetRequest |
| `engine.js` | asks the native handler | consults lists it carries |

Xcode builds Safari's copy from `Shared/` + `Safari/`; the script builds
Chrome's from `Shared/` + `Chrome/`. The shared files are byte-identical in
both, so the browsers cannot drift apart in how a block is handled — only in
where the verdict comes from.

### Why Chrome carries its own lists

A sandboxed Mac App Store app cannot install a native messaging host manifest
into `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`, so
Chrome has no way to reach the Swift engine. Using native messaging would mean
giving up App Store distribution. The extension is therefore self-contained,
and **its lists are independent of the Mac and iOS apps** — nothing syncs
between them, which keeps the "nothing leaves the device" claim intact.

### The same split of labour as Safari

- **declarativeNetRequest** stops the request before it is sent. Sub-resource
  requests are blocked; top-level navigations are *redirected* to the block
  page, so the user still gets an explanation.
- **The service worker** handles only what rules cannot express — a heuristic
  verdict on a host no list has seen — and records what was blocked so the
  block page can describe it.

That division is not a stylistic choice. `webNavigation.onBeforeNavigate` only
*observes* a navigation; it cannot cancel one. Blocking from the service worker
meant the page had already begun loading and running scripts by the time the
redirect landed — a blocked site still managed to pop up its own dialogs, and
for a malware host that means the attack had already run. Anything on a list is
therefore stopped declaratively.

A heuristic verdict is still reached in JavaScript and so still races, by
nature: the host is unknown until it is examined. That is the cost of catching
sites no list has yet seen, and it applies only to them.

Chrome is the one place that carries the **full** catalog, phishing included:
its budget is 30,000 static rules guaranteed, and `requestDomains` packs
~42,900 hosts into about 925 rules. WebKit could not take the same list, which
is why Safari routes phishing through the engine instead.

Two limits shape the generated rules, and the build fails rather than silently
exceeding either: rules are packed to a byte budget because each must stay
under 2 KB once compiled (a fixed 50 domains per rule put 123 over), and no
`regexFilter` is used at all because Chrome caps those at 1,000 — translating
Safari's regex rules directly would have blown that on the first feed.

### Installing it

There is no local installer, and that is Chrome's doing rather than an
omission. Chrome 44 removed external installs from a local `.crx` on macOS, and
an external-extension entry's `external_update_url` must point at the Chrome
Web Store. A sandboxed App Store app could not write into Chrome's support
directory to place one anyway — the same constraint that ruled out native
messaging. **The Web Store listing is the installer.**

```bash
./scripts/build_chrome.sh              # assemble into dist/chrome
./scripts/build_chrome.sh --package    # + a Web Store zip, version-stamped
```

`--package` produces `dist/browseguard-chrome-<version>.zip` (~880 KB) ready to
upload at the [developer console](https://chrome.google.com/webstore/devconsole);
the version is read from `MARKETING_VERSION` so the extension and the apps stay
in step. `scripts/finish_chrome_manifest.py` checks the bundle before it is
packaged and fails rather than shipping something Chrome would reject: every
manifest reference and script import must resolve, and the rule count, per-rule
size and regex count must all be within Chrome's limits.

Once published, set `BROWSEGUARD_CHROME_URL` in `project.yml` to the listing
and the macOS app offers it on the Overview screen. Left empty, the offer is
hidden rather than linking somewhere that does not exist.

For a managed fleet there is one other legitimate route: the
`ExtensionInstallForcelist` policy via a configuration profile or MDM. It still
requires the extension to be on the Web Store, and Chrome marks the browser as
managed by your organization.

For local testing, load `dist/chrome` unpacked from `chrome://extensions` with
developer mode on.

### Keeping the heuristics honest

Chrome has no native side, so `HeuristicScanner` exists twice: once in Swift,
once in `WebExtension/Shared/heuristics.js`. Two copies of the same rules drift
unless something stops them, so both run against `Tests/heuristic-vectors.json`:

```bash
swift scripts/make_heuristic_vectors.swift   # regenerate from Swift
node scripts/test_heuristics.mjs             # check JavaScript agrees
```

The Swift suite checks the same file, so a disagreement fails on both sides.
This paid for itself immediately: the first run found that Swift's IDN
homograph rule had **never fired**, because it relied on `URL.host` to decode
punycode and Apple's `URL` hands the encoded form back. Both now decode
punycode properly and flag two shapes — a label mixing alphabets (`аpple.com`),
and a whole-script lookalike whose confusable skeleton matches a brand
(`аррӏе.com`, entirely Cyrillic). A domain written wholly in one non-Latin
script, like `βόλος.com`, stays clean.


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
so the logic is exercised headlessly.

| Suite | Tests | Covers |
| --- | --- | --- |
| `EngineTests` | 61 | Host canonicalization, suffix matching (including the `notdoubleclick.net` near-miss), heuristic true and false positives, the allowlist beating a malware listing, bypass expiry, rule-limit truncation, block-over-allow ordering, and that a compiled `url-filter` anchors at the host rather than matching a query string |
| `EntitlementTests` | 9 | Expiry and grace boundaries, grace needing a product, a lapse keeping the saved choice, the App Group round trip, the blocker reading the same file, the product list |
| `DuplicateInstallTests` | 7 | Duplicate detection, which copy is running, the prompt once per version |
| `CatalogCacheTests` | 4 | The catalog is decoded once and reloaded when the file changes |
| `HeuristicVectorTests` | 1 | The Swift scanner agrees with `Tests/heuristic-vectors.json` |

Other checks that run outside Xcode:

```bash
python3 scripts/test_build_feeds.py     # 22 tests: the feed builder, no network
node scripts/test_heuristics.mjs        # JavaScript heuristics against the same vectors
./scripts/single-copy.sh                # one installed, running and registered copy
```

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
- Access is sold through StoreKit 2 auto-renewing subscriptions, not license keys
  (Guideline 3.1.1). See [Subscription](#subscription).
- The apps show a paywall until a subscription is active. Say in the App Review
  notes how a reviewer gets past it: a sandbox purchase, or the Restore Purchases
  button on a sandbox account.

---

## Layout

```
Shared/
  Core/        ThreatCategory, Blocklist, URLNormalizer, HeuristicScanner,
               Verdict, ProtectionEngine, ContentRuleCompiler, AppGroup,
               ExtensionBridge, CoalescingRunner, ConfiguredURL,
               DuplicateInstall, DuplicateInstallPrompt
  Entitlement/ EntitlementRecord (read by every process),
               SubscriptionStore (app only, talks to StoreKit)
  Storage/     ProtectionSettings, Allowlist, UserBlocklist, BlockEvent,
               SharedStore, AllowlistStore, UserBlocklistStore, EventLogStore
  Sync/        CloudSync
  Updates/     BlocklistUpdater
  ViewModels/  ProtectionCoordinator
  Views/       shared SwiftUI: PaywallView, SiteCheckerView, ActivityList,
               AllowlistEditor, BlockedSitesEditor, ChromeExtensionCard, Theme
  Support/     Objective-C exception barrier (BGExceptionBarrier)
  Resources/   bundled baseline blocklists
iOS/ macOS/ tvOS/      per-platform app targets; each has its own Views/
                       (macOS also has the duplicate-install scanner and remover)
ContentBlocker/        request handler and rule-list resources, shared by both
                       platform extensions
WebExtension/          native handler, manifests, background.js, content.js,
                       block page, popup
StoreKit/              BrowseGuard.storekit, local product definitions
scripts/               build_feeds.py, build_chrome.sh, finish_chrome_manifest.py,
                       single-copy.sh, uninstall.sh, heuristic vector tools
Tests/                 engine, entitlement, duplicate-install and heuristic tests
dist/                  generated feeds and the Chrome build (git-ignored)
```
