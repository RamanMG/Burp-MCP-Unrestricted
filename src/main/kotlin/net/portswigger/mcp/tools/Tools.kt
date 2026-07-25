package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.Component
import java.awt.Container
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JButton
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import javax.swing.text.JTextComponent

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

// UNRESTRICTED FORK: per-call truncation control. null -> default 5000; <=0 -> no truncation.
private fun truncateTo(serialized: String, maxLength: Int?): String {
    val limit = maxLength ?: 5000
    return if (limit > 0 && serialized.length > limit) {
        serialized.substring(0, limit) + "... (truncated)"
    } else {
        serialized
    }
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }

    // ---------------------------------------------------------------------
    // UNRESTRICTED FORK additions
    // ---------------------------------------------------------------------

    mcpPaginatedTool<GetProxyHttpHistoryLatest>(
        "Displays proxy HTTP history NEWEST-FIRST (offset 0 = the most recent request). " +
                "Optional 'regex' filters items by content; optional 'maxLength' overrides per-item truncation " +
                "(<=0 disables truncation, default 5000). Prefer this over get_proxy_http_history to read the LATEST captured traffic."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val cap = maxLength
        val rx = regex
        val history = if (rx != null) {
            val compiledRegex = Pattern.compile(rx)
            api.proxy().history { it.contains(compiledRegex) }
        } else {
            api.proxy().history()
        }

        history.asReversed().asSequence().map { truncateTo(Json.encodeToString(it.toSerializableForm()), cap) }
    }

    mcpPaginatedTool<GetSiteMap>(
        "Displays entries from Burp's target site map (the discovered URL/endpoint inventory, including spidered URLs that have no response yet). " +
                "Optional 'host' filters by host substring; optional 'regex' filters by request+response content; optional 'maxLength' controls truncation. " +
                "Use this to map the target's attack surface."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "site map")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Site map access denied by Burp Suite")
        }

        val cap = maxLength
        val hostFilter = host
        val compiledRegex = regex?.let { Pattern.compile(it) }

        api.siteMap().requestResponses().asSequence()
            .filter { rr ->
                hostFilter == null ||
                        (rr.request()?.httpService()?.host()?.contains(hostFilter, ignoreCase = true) == true)
            }
            .map { it.toSerializableForm() }
            .filter { ser ->
                compiledRegex == null ||
                        compiledRegex.matcher((ser.request ?: "") + "\n" + (ser.response ?: "")).find()
            }
            .map { truncateTo(Json.encodeToString(it), cap) }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpTool<ActiveScanUrl>(
            "Starts a Burp active audit (active scan) of a single URL. Poll get_scanner_issues to read findings as they appear. Professional only."
        ) {
            val request = HttpRequest.httpRequestFromUrl(url)
            val audit = api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
            )
            audit.addRequest(request)
            api.logging().logToOutput("MCP active scan started for $url")
            "Active audit started for $url. Status: ${audit.statusMessage()}. Use get_scanner_issues to read findings."
        }

        mcpTool<CrawlUrl>(
            "Starts a Burp crawl (spider) from one or more seed URLs to discover content. Professional only."
        ) {
            val crawl = api.scanner().startCrawl(
                CrawlConfiguration.crawlConfiguration(*seedUrls.toTypedArray())
            )
            api.logging().logToOutput("MCP crawl started for ${seedUrls.joinToString()}")
            "Crawl started for ${seedUrls.size} seed URL(s). Status: ${crawl.statusMessage()}."
        }
    }

    // ---- Repeater UI automation (Swing tree; Montoya exposes no Repeater send/read/group) ----

    mcpTool<SwingDump>(
        "Diagnostic: dumps Burp's Swing component tree (class names, button labels, tab titles, editor text lengths). Use to map the UI for Repeater automation."
    ) {
        val frame = api.userInterface().swingUtils().suiteFrame()
        val sb = StringBuilder()
        onEdt { dumpSwingTree(frame, 0, sb, maxDepth ?: 22, showingOnly ?: false) }
        truncateTo(sb.toString(), maxLength ?: 18000)
    }

    mcpTool<RepeaterSend>(
        "Drives Burp Repeater: selects the Repeater tab (and named sub-tab if given), then clicks a button. Target it by 'buttonIndex' (position in the showing+enabled inventory, most reliable for Burp's unlabeled Send button) or 'buttonLabel' (text/tooltip/accessible-name substring). With no target it inventories every showing+enabled button (with screen bounds) so the right one can be picked."
    ) {
        onEdt {
            val frame = api.userInterface().swingUtils().suiteFrame()
            val repeaterRoot = findRepeaterRoot(frame) ?: return@onEdt "Could not locate the Repeater tab"
            tabName?.let { selectRepeaterSubTab(repeaterRoot, it) }
            val buttons = allComponents(repeaterRoot).filterIsInstance<JButton>()
                .filter { it.isShowing && it.isEnabled }
                .toList()
            fun desc(i: Int, b: JButton): String {
                val pt = runCatching { b.locationOnScreen }.getOrNull()
                return "#$i[text='${b.text}' tip='${b.toolTipText}' acc='${accName(b)}' cmd='${b.actionCommand}' cls=${b.javaClass.simpleName} @${pt?.x},${pt?.y} ${b.width}x${b.height}]"
            }
            val target: JButton? = when {
                buttonIndex != null -> buttons.getOrNull(buttonIndex)
                buttonLabel != null -> buttons.firstOrNull { buttonSignature(it).contains(buttonLabel.lowercase()) }
                else -> buttons.firstOrNull { buttonSignature(it).contains("send") }
            }
            if (target == null) {
                return@onEdt "No target (buttonIndex=$buttonIndex, buttonLabel=$buttonLabel). Showing buttons → " +
                    buttons.mapIndexed { i, b -> desc(i, b) }.joinToString("; ")
            }
            target.doClick()
            "Clicked ${desc(buttons.indexOf(target), target)} in Repeater"
        }
    }

    mcpTool<RepeaterRead>(
        "Reads the visible message editors of the active Repeater sub-tab (best-effort scrape of request/response panes), leftmost-first. Call shortly after repeater_send."
    ) {
        onEdt {
            val frame = api.userInterface().swingUtils().suiteFrame()
            val repeaterRoot = findRepeaterRoot(frame) ?: return@onEdt "Could not locate the Repeater tab"
            val editors = allComponents(repeaterRoot).filterIsInstance<JTextComponent>()
                .filter { it.isShowing && (it.document?.length ?: 0) > 0 }
                .sortedBy { runCatching { it.locationOnScreen.x }.getOrDefault(0) }
                .toList()
            if (editors.isEmpty()) return@onEdt "<no readable editor text in the active Repeater tab>"
            editors.mapIndexed { i, e ->
                val x = runCatching { e.locationOnScreen.x }.getOrDefault(-1)
                "--- pane#$i (screenX=$x, len=${e.document.length}) ---\n${e.text}"
            }.joinToString("\n\n").let { truncateTo(it, maxLength ?: 8000) }
        }
    }

    mcpTool<RepeaterRename>(
        "Renames a Repeater sub-tab (matched by current title substring) to a new title."
    ) {
        onEdt {
            val frame = api.userInterface().swingUtils().suiteFrame()
            val repeaterRoot = findRepeaterRoot(frame) ?: return@onEdt "Could not locate the Repeater tab"
            val subTabbed = allComponents(repeaterRoot).filterIsInstance<JTabbedPane>()
                .firstOrNull { tp -> (0 until tp.tabCount).any { (tp.getTitleAt(it) ?: "").contains(fromName) } }
                ?: return@onEdt "No Repeater sub-tab title matching '$fromName'"
            val i = (0 until subTabbed.tabCount).first { (subTabbed.getTitleAt(it) ?: "").contains(fromName) }
            subTabbed.setTitleAt(i, toName)
            "Renamed Repeater tab '$fromName' -> '$toName'"
        }
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

// ---- Swing-tree helpers for Repeater UI automation ----

private fun <T> onEdt(block: () -> T): T {
    if (SwingUtilities.isEventDispatchThread()) return block()
    val holder = arrayOfNulls<Any?>(1)
    SwingUtilities.invokeAndWait { holder[0] = block() }
    @Suppress("UNCHECKED_CAST")
    return holder[0] as T
}

private fun allComponents(root: Component): Sequence<Component> = sequence {
    yield(root)
    if (root is Container) for (child in root.components) yieldAll(allComponents(child))
}

private fun findRepeaterRoot(frame: Component): Component? {
    val topTabbed = allComponents(frame).filterIsInstance<JTabbedPane>()
        .firstOrNull { tp -> (0 until tp.tabCount).any { (tp.getTitleAt(it) ?: "").equals("Repeater", true) } }
        ?: return null
    val idx = (0 until topTabbed.tabCount).first { (topTabbed.getTitleAt(it) ?: "").equals("Repeater", true) }
    topTabbed.selectedIndex = idx
    return topTabbed.getComponentAt(idx)
}

private fun selectRepeaterSubTab(repeaterRoot: Component, name: String) {
    val subTabbed = allComponents(repeaterRoot).filterIsInstance<JTabbedPane>()
        .firstOrNull { tp -> (0 until tp.tabCount).any { (tp.getTitleAt(it) ?: "").contains(name) } } ?: return
    val i = (0 until subTabbed.tabCount).first { (subTabbed.getTitleAt(it) ?: "").contains(name) }
    subTabbed.selectedIndex = i
}

private fun accName(c: Component): String? = runCatching { c.accessibleContext?.accessibleName }.getOrNull()

private fun buttonSignature(b: JButton): String =
    listOfNotNull(b.text, b.toolTipText, accName(b), b.actionCommand).joinToString(" ").lowercase()

private fun dumpSwingTree(c: Component, depth: Int, sb: StringBuilder, maxDepth: Int, showingOnly: Boolean) {
    if (depth > maxDepth) return
    val extra = when (c) {
        is JButton -> " [BTN text='${c.text}' tip='${c.toolTipText}' acc='${accName(c)}' cmd='${c.actionCommand}' en=${c.isEnabled} show=${c.isShowing}]"
        is JTabbedPane -> " [TABS ${(0 until c.tabCount).joinToString("|") { c.getTitleAt(it) ?: "?" }} sel=${c.selectedIndex}]"
        is JTextComponent -> " [EDITOR len=${c.document?.length ?: 0} edit=${c.isEditable} show=${c.isShowing}]"
        else -> ""
    }
    if (extra.isNotEmpty() && (!showingOnly || c.isShowing)) {
        sb.append("·".repeat(depth)).append(c.javaClass.simpleName).append(extra).append('\n')
    }
    if (c is Container) for (child in c.components) dumpSwingTree(child, depth + 1, sb, maxDepth, showingOnly)
}

@Serializable
data class SwingDump(val maxDepth: Int? = null, val maxLength: Int? = null, val showingOnly: Boolean? = null)

@Serializable
data class RepeaterSend(
    val tabName: String? = null,
    val buttonLabel: String? = null,
    val buttonIndex: Int? = null
)

@Serializable
data class RepeaterRead(val maxLength: Int? = null)

@Serializable
data class RepeaterRename(val fromName: String, val toName: String)

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)

// UNRESTRICTED FORK param classes
@Serializable
data class GetProxyHttpHistoryLatest(
    override val count: Int,
    override val offset: Int,
    val regex: String? = null,
    val maxLength: Int? = null
) : Paginated

@Serializable
data class GetSiteMap(
    override val count: Int,
    override val offset: Int,
    val host: String? = null,
    val regex: String? = null,
    val maxLength: Int? = null
) : Paginated

@Serializable
data class ActiveScanUrl(val url: String)

@Serializable
data class CrawlUrl(val seedUrls: List<String>)
