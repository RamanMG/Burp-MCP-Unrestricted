package net.portswigger.mcp

import io.modelcontextprotocol.kotlin.sdk.CallToolResultBase
import io.modelcontextprotocol.kotlin.sdk.EmptyRequestResult
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.client.StdioClientTransport
import kotlinx.io.asSink
import kotlinx.io.asSource
import kotlinx.io.buffered
import org.slf4j.LoggerFactory
import java.io.InputStream
import java.io.OutputStream

class TestStdioMcpClient {
    private val logger = LoggerFactory.getLogger(TestStdioMcpClient::class.java)
    private val mcp: Client = Client(clientInfo = Implementation(name = "test-mcp-client", version = "1.0.0"))

    suspend fun connectToServer(input: InputStream, output: OutputStream) {
        val transport = StdioClientTransport(
            input = input.asSource().buffered(),
            output = output.asSink().buffered()
        )

        mcp.connect(transport)
        logger.info("Connected to server")
    }

    suspend fun ping(): EmptyRequestResult {
        return mcp.ping()
    }

    suspend fun listTools(): List<Tool> {
        return mcp.listTools().tools
    }

    suspend fun callTool(toolName: String, arguments: Map<String, Any>): CallToolResultBase? {
        return mcp.callTool(toolName, arguments)
    }

    suspend fun close() {
        mcp.close()
        logger.info("MCP client closed successfully.")
    }
}
