package net.portswigger.mcp

import net.portswigger.mcp.config.McpConfig

sealed class ServerState {
    data object Starting : ServerState()
    data object Running : ServerState()
    data object Stopping : ServerState()
    data object Stopped : ServerState()
    data class Failed(val exception: Throwable) : ServerState()
}

interface ServerManager {
    fun start(config: McpConfig, callback: (ServerState) -> Unit)
    fun stop(callback: (ServerState) -> Unit)
    fun shutdown()
}