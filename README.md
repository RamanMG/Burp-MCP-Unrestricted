# Burp MCP Server (Unrestricted)

> **Unofficial fork.** Original project: [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) by PortSwigger.
> **Tweaked By Raman_MG.**
>
> This is **not** an official PortSwigger release, and is not affiliated with or endorsed by PortSwigger.
> For the supported official extension, install **MCP Server** from the Burp BApp Store.

Connect Burp Suite to an AI client over the [Model Context Protocol](https://modelcontextprotocol.io/).

This fork keeps everything the upstream extension does and adds the tooling I kept needing during real
testing work: reading the newest proxy traffic first, pulling the site map, driving scans and crawls,
and automating Repeater.

---

## Why this fork exists

The official extension is built for a short, supervised session: a human watching, approving each action,
on a target with a small amount of traffic. That is a reasonable default and it is the right one for most
people.

It is the wrong shape for an agent working a real engagement. Below is what an AI client can and cannot
do through each version. Every row was verified against the source, not assumed.

| Capability | Official MCP Server | This fork |
|---|---|---|
| **Read the newest request** | Only through `get_proxy_http_history`, which returns history **oldest-first**. On a project with 100k captured requests, the current one sits at offset ~100000. | `get_proxy_http_history_latest` returns **newest-first**. The request you just made is at offset 0. |
| **Response size per item** | Hardcoded **5000-character truncation** on every item, applied by a private function with no parameter to override it. A 40KB JSON response is cut at 5000 and the rest is unreachable. | `maxLength` on every read tool. Pass `0` to disable truncation and get the whole body. |
| **See the endpoint inventory** | **No tool reaches it.** Upstream calls `siteMap().issues()` to list scanner findings, but never `siteMap().requestResponses()`, so the discovered URL inventory (including spidered URLs with no response yet) is unreachable. | `get_site_map` exposes `requestResponses()`, with `host` and `regex` filters. |
| **Start a scan** | **Read-only.** `get_scanner_issues` reads findings, but nothing can start an audit. | `active_scan_url` starts an audit. `crawl_url` starts a crawl. (Professional.) |
| **Use Repeater** | **Write-only.** `create_repeater_tab` puts a request into Repeater, then the agent is stuck: no way to send it, and no way to read the response. | `repeater_send`, `repeater_read`, `repeater_rename`. Full loop. |
| **Sustained work** | Confirmation dialog before **each** HTTP request and **each** data read. | Off by default, still switchable in the `MCP+` tab. |
| **Edit Burp config** | Off by default. | On by default. |

To be exact about one thing, since it gets repeated: **the official extension does not impose a fixed
cap of 1000 URLs.** Pagination `count` is caller-controlled with no ceiling. The limits that actually
bite are the three real ones above: oldest-first ordering, the 5000-character truncation, and the
missing site map.

### What that means on a long engagement

Take a wide-scope program worked over several months. Proxy history does not stay small. Browse the app,
run a crawl, let the scanner work, replay a few hundred requests a day, and the history passes 100,000
entries without anything unusual happening.

At that size the official extension's ordering stops being an inconvenience and becomes a wall. The agent
asks for proxy history and receives requests from the first day of the engagement. To reach what you just
sent, it has to page forward through six figures of stale traffic, and each page burns a round trip and a
slice of a finite context window. The traffic is right there in Burp. The agent simply cannot get to the
end of the list. `get_proxy_http_history_latest` is one line of reordering, and it turns that from
impossible into offset 0.

The truncation compounds it. Interesting responses are usually the large ones: a verbose stack trace, a
bulk export, a GraphQL introspection result, an API listing that leaks fields the UI redacts. Those are
exactly the responses that blow past 5000 characters, so the agent reads the first 5000 and the finding
sits in the part that got cut.

The site map gap is the third. Proxy history tells you what was *requested*. The site map tells you what
*exists*, including URLs a crawl discovered but never fetched. That inventory is the attack surface.
Upstream reaches into the site map object for scanner issues but never for the request/response
inventory, so an agent can read what Burp *found wrong* and not what Burp *found*.

None of this is a criticism of the upstream design. A tool built for a supervised ten-minute session
makes different tradeoffs than one driving a months-long engagement. This fork is the second shape.

---

## What is different in this fork

Two kinds of change: **new tools** and **changed defaults**. Full technical detail, including the exact
upstream lines touched, is in [CHANGES.md](CHANGES.md).

### New MCP tools (8)

| Tool | What it does |
|---|---|
| `get_proxy_http_history_latest` | Proxy history **newest-first** (offset 0 = most recent request). Upstream serves oldest-first only, so reading fresh traffic meant paging to the end. Supports `regex` filtering and `maxLength`. |
| `get_site_map` | Reads Burp's target site map, which is the discovered URL/endpoint inventory including spidered URLs that have no response yet. Filter by `host` substring or `regex`. |
| `active_scan_url` | Starts a Burp active audit against a single URL. Poll `get_scanner_issues` for findings. **Professional only.** |
| `crawl_url` | Starts a Burp crawl from one or more seed URLs. **Professional only.** |
| `repeater_send` | Selects the Repeater tab (and a named sub-tab) and clicks Send. Target by `buttonIndex` or `buttonLabel`; with no target it inventories every visible button so you can pick one. |
| `repeater_read` | Scrapes the visible request/response editors of the active Repeater sub-tab, leftmost pane first. |
| `repeater_rename` | Renames a Repeater sub-tab, matched by a substring of its current title. |
| `swing_dump` | Diagnostic. Dumps Burp's Swing component tree (buttons, tab titles, editor lengths) so the Repeater automation above can be mapped on your own Burp build. |

The Repeater tools drive the Swing UI directly, because the Montoya API exposes no Repeater
send/read/rename surface. That makes them the most build-sensitive part of this fork: if a Burp update
reshuffles the UI, run `swing_dump` to find the new button index.

Every new read tool also accepts `maxLength`, which overrides the hardcoded 5000-character truncation
upstream applies per item. Pass `0` or a negative value to disable truncation entirely.

### Changed defaults

| Setting | Upstream | This fork |
|---|---|---|
| `requireHttpRequestApproval` | `true` | **`false`** |
| `requireDataAccessApproval` | `true` | **`false`** |
| `configEditingTooling` | `false` | **`true`** |
| Extension name | `Burp MCP Server` | `Burp MCP Server (Unrestricted)` |
| Suite tab | `MCP` | `MCP+` |

**Read this before installing.** Upstream shows a confirmation dialog before the AI client sends an HTTP
request or reads captured data. This fork turns those dialogs off by default, which is the entire point
of the "unrestricted" name: an agent driving a long test session should not stop every few seconds for a
click. The tradeoff is real. With the defaults as shipped, **a connected MCP client can send HTTP
requests and read your proxy history without asking you first**, and config-editing tooling is enabled.

Nothing is removed, only re-defaulted. **Every prompt can be switched back on in the `MCP+` tab**, which
gives you upstream behaviour. If you would rather opt in than opt out, flip the three toggles after first
load, or change the defaults in
[`McpConfig.kt`](src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt) and rebuild.

The server still binds to `127.0.0.1:9876` by default, as upstream. Keep it there. Do not expose it on a
routable interface with the approval prompts disabled.

---

## Install

### Option A: prebuilt jar

Download `burp-mcp-unrestricted-1.3.0.jar` from the
**[latest release](https://github.com/RamanMG/Burp-MCP-Unrestricted/releases/latest)**. It is a
ready-to-load build with the stdio MCP proxy already embedded, so it is the only file you need.

1. Burp Suite → **Extensions** → **Add**
2. Extension type: **Java**
3. Select the jar, then **Next**

An `MCP+` tab should appear in the Burp suite tab bar.

### Option B: build from source

Requires **Java 21** and the `jar` command on your `PATH`.

```bash
git clone https://github.com/RamanMG/Burp-MCP-Unrestricted.git
cd Burp-MCP-Unrestricted
./gradlew embedProxyJar
```

Output lands at `build/libs/burp-mcp-all.jar`. Load it exactly as in Option A.

Use `embedProxyJar`, not plain `build`: it packs the stdio proxy from `libs/` into the extension jar so a
stdio MCP client works without a second file.

---

## Configuration

Configured through the Burp UI in the `MCP+` tab.

- **Enabled** toggles the MCP server.
- **Enable tools that can edit your config** exposes the config-editing tools (on by default in this fork).
- **Advanced options** sets host and port. Default `http://127.0.0.1:9876`.
- The approval toggles described above live here too.

### Claude Desktop

The extension ships an installer that writes the Claude Desktop config for you. Use the installer button
in the `MCP+` tab, or edit the config by hand at
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "burp": {
      "command": "<path to the Java executable packaged with Burp>",
      "args": [
        "-jar",
        "/path/to/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876"
      ]
    }
  }
}
```

Restart Claude Desktop with Burp running and the extension loaded.

---

## Manual installation

For any client other than Claude Desktop, or if you would rather not use the installer button.

**SSE:** point the client at the server URL. Depending on the client, with or without the `/sse` path:

```
http://127.0.0.1:9876
http://127.0.0.1:9876/sse
```

**Stdio:** for clients that only speak stdio, use the packaged proxy. Extract it with the installer
option in the extension, then:

```
/path/to/packaged/burp/java -jar /path/to/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

Proxy server source: [PortSwigger/mcp-proxy](https://github.com/PortSwigger/mcp-proxy).

---

## Adding your own tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. Create a `@Serializable` data
class holding the parameters the LLM supplies, then register it with `mcpTool<YourClass>("description")`.

The tool name is auto-derived from the data class name, converted to snake_case: `GetSiteMap` becomes
`get_site_map`. Return a string, or richer `PromptMessageContent`, to send data back to the LLM. Extend
the `Paginated` interface for automatic pagination.

---

## Compatibility

- Burp Suite **Professional** and **Community**. `active_scan_url` and `crawl_url` register only on
  Professional, since scanning is a Pro feature. The other six tools work on both editions.
- Built against upstream v1.3.0 of the Montoya-based extension, on Java 21.

---

## Credits and licence

The overwhelming majority of this code is PortSwigger's. Original authors: **Daniel S** and
**Daniel Allen**, PortSwigger. Original repository:
[github.com/PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server).

Modifications in this fork by **Raman_MG**.

Licensed under the **GNU General Public License v3.0**, the same licence as upstream. The full text is in
[LICENSE](LICENSE), unmodified. Per GPLv3 section 5(a), the changes made to the original work are
documented in [CHANGES.md](CHANGES.md) and are marked inline in the source with `UNRESTRICTED FORK`
comments.

This extension is for authorised security testing only: systems you own, or systems you have written
permission to test.
