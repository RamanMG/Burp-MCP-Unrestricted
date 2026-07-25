# Changes from upstream

This document satisfies **GPLv3 section 5(a)**: a statement of the modifications made to the original
work, and the date they were made.

- **Original work:** [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server), by Daniel S
  and Daniel Allen (PortSwigger), licensed GPL-3.0.
- **Base version:** 1.3.0
- **Modified by:** Raman_MG
- **Date of modification:** 2 June 2026

Three files are modified. No upstream file is deleted, and no upstream capability is removed. All
additions are marked inline in the source with `UNRESTRICTED FORK` comments.

---

## 1. `src/main/kotlin/net/portswigger/mcp/ExtensionBase.kt`

Cosmetic only, so the fork is distinguishable from the official extension when both are known to a user.

| | Upstream | Fork |
|---|---|---|
| Extension name | `Burp MCP Server` | `Burp MCP Server (Unrestricted)` |
| Suite tab title | `MCP` | `MCP+` |

## 2. `src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt`

Three default values changed. **Behaviour is only re-defaulted, not removed.** Each remains switchable
in the `MCP+` tab, and setting all three back to the upstream values restores upstream behaviour exactly.

| Setting | Upstream default | Fork default | Effect of the fork default |
|---|---|---|---|
| `requireHttpRequestApproval` | `true` | `false` | The MCP client can send HTTP requests without a per-request confirmation dialog. |
| `requireDataAccessApproval` | `true` | `false` | The MCP client can read captured data (proxy history, site map) without a per-access confirmation dialog. |
| `configEditingTooling` | `false` | `true` | Tools that can edit Burp configuration are registered by default. |

Rationale: an agent driving a long testing session is unusable if every request and every history read
blocks on a UI click. The cost is that a connected client can act without prompting, so the tradeoff is
documented prominently in the README rather than buried here.

## 3. `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`

The substantive change: **8 new MCP tools**, plus a truncation helper. Roughly 260 added lines. No
upstream tool is modified or removed.

### Added helper

- `truncateTo(serialized, maxLength)` gives per-call control over output truncation. Upstream applies a
  fixed 5000-character cap per item via `truncateIfNeeded`. The new helper defaults to the same 5000 and
  disables truncation when passed a value of `0` or less. Upstream's `truncateIfNeeded` is untouched and
  still used by upstream tools.

### Added tools: reading captured data

- **`get_proxy_http_history_latest`** (`GetProxyHttpHistoryLatest`) reverses the proxy history so offset
  0 is the most recent request. Upstream's `get_proxy_http_history` is oldest-first, so reaching current
  traffic required paging to the end of the history. Optional `regex` content filter and `maxLength`.
- **`get_site_map`** (`GetSiteMap`) exposes `api.siteMap().requestResponses()`. Upstream calls
  `api.siteMap().issues()` for `get_scanner_issues` but never `requestResponses()`, so the discovered
  URL inventory had no tool. It includes URLs found by crawling that have no response yet, so it reads
  as an endpoint inventory rather than a traffic log. Optional `host` substring filter, `regex` filter
  over request+response, and `maxLength`.

Both call the same `checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, ...)` gate that upstream data
tools use, so the fork does not bypass the approval mechanism. It only changes that mechanism's default
(see section 2).

### Added tools: scanner (Professional only)

Both are registered inside an existing `api.burpSuite().version().edition() == PROFESSIONAL` guard, so
they do not appear on Community.

- **`active_scan_url`** (`ActiveScanUrl`) starts an audit via
  `AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)`.
- **`crawl_url`** (`CrawlUrl`) starts a crawl via `CrawlConfiguration.crawlConfiguration(seedUrls)`.

New imports: `AuditConfiguration`, `BuiltInAuditConfiguration`, `CrawlConfiguration`.

### Added tools: Repeater automation

The Montoya API exposes no way to send, read, or rename a Repeater tab. These tools therefore walk
Burp's Swing component tree from `api.userInterface().swingUtils().suiteFrame()` and act on the widgets
directly. All Swing work is marshalled onto the Event Dispatch Thread through a new `onEdt` helper.

- **`repeater_send`** (`RepeaterSend`) selects the Repeater tab, optionally a named sub-tab, then clicks
  a button chosen by `buttonIndex` or `buttonLabel`. Burp's Send button carries no text, so index
  targeting is usually the reliable path. Called with no target, it returns an inventory of every
  showing and enabled button with screen coordinates, so the correct index can be identified.
- **`repeater_read`** (`RepeaterRead`) collects visible `JTextComponent` editors in the active sub-tab,
  sorted left to right by screen X, which puts the request pane before the response pane.
- **`repeater_rename`** (`RepeaterRename`) retitles a sub-tab matched by title substring.
- **`swing_dump`** (`SwingDump`) dumps the component tree with button labels, tooltips, accessible
  names, action commands, tab titles and editor lengths. It exists to make the three tools above
  mappable on a given Burp build.

Supporting private helpers added: `onEdt`, `allComponents`, `findRepeaterRoot`, `selectRepeaterSubTab`,
`accName`, `buttonSignature`, `dumpSwingTree`.

New imports: `java.awt.Component`, `java.awt.Container`, `javax.swing.JButton`,
`javax.swing.JTabbedPane`, `javax.swing.SwingUtilities`, `javax.swing.text.JTextComponent`.

**Known fragility:** because these tools depend on Burp's UI layout rather than a public API, a Burp
release that reorganises the Repeater UI can change the button index or the pane ordering. `swing_dump`
is the recovery path. This is inherent to the approach, not a defect that a future patch can remove.

---

## 4. `build.gradle.kts`

Build metadata only, no functional change.

- `Built-By` was `System.getProperty("user.name")`, which stamps the building machine's OS username into
  the released jar manifest. Replaced with the fixed string `Raman_MG` so a build never leaks a username.
- Added a `Fork-Of` manifest attribute pointing at the upstream repository, so a jar found in isolation
  identifies its origin.

`Implementation-Vendor` is deliberately left as `PortSwigger`, since the packaged code is theirs.

---

## Not changed

For clarity about what this fork does **not** touch:

- `LICENSE` is upstream's GPL-3.0 text, byte for byte.
- The security layer (`security/DataAccessSecurity.kt`, `security/HttpRequestSecurity.kt`,
  `security/SecurityUtils.kt`) is unmodified. Approval checks still run; only their default state
  changed.
- Credential filtering (`filterConfigCredentials`) is unmodified, so config reads still redact secrets.
- All upstream tools, the SSE and stdio transports, the Claude Desktop installer, and the test suite are
  unmodified.
