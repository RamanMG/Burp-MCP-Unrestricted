package net.portswigger.mcp.providers

import burp.api.montoya.logging.Logging
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import kotlin.io.path.exists
import kotlin.io.path.readText

class ProxyJarManager(private val logging: Logging) {

    companion object {
        private const val PROXY_JAR_NAME = "mcp-proxy-all.jar"
    }

    fun getProxyJar(): Path {
        val proxyJarPath = getBurpProxyJarPath()
        val versionFilePath = proxyJarPath.resolveSibling("$PROXY_JAR_NAME.version")

        if (!proxyJarPath.parent.exists()) {
            try {
                Files.createDirectories(proxyJarPath.parent)
            } catch (e: IOException) {
                throw RuntimeException("Failed to create directory: ${proxyJarPath.parent}", e)
            }
        }

        val resourceStream = javaClass.classLoader.getResourceAsStream(PROXY_JAR_NAME)
            ?: throw RuntimeException("Could not find $PROXY_JAR_NAME in extension resources")

        val digest = MessageDigest.getInstance("SHA-256")
        val resourceBytes = resourceStream.readAllBytes()
        val resourceHash = digest.digest(resourceBytes).joinToString("") { "%02x".format(it) }

        val needsExtraction =
            !proxyJarPath.exists() || !versionFilePath.exists() || versionFilePath.readText().trim() != resourceHash

        if (needsExtraction) {
            try {
                val tempFile = Files.createTempFile(proxyJarPath.parent, "temp-", ".jar")
                Files.write(tempFile, resourceBytes)

                Files.move(tempFile, proxyJarPath, StandardCopyOption.REPLACE_EXISTING)

                Files.writeString(versionFilePath, resourceHash)

                if (!System.getProperty("os.name").lowercase().contains("win")) {
                    proxyJarPath.toFile().setExecutable(true)
                }

                logging.logToOutput("Extracted proxy jar to: $proxyJarPath")
            } catch (e: IOException) {
                throw RuntimeException("Failed to extract proxy jar to: $proxyJarPath", e)
            }
        }

        return proxyJarPath
    }

    private fun getBurpProxyJarPath(): Path {
        val os = System.getProperty("os.name").lowercase()
        val home = System.getProperty("user.home")

        val basePath = when {
            os.contains("win") -> Path.of(home, "AppData", "Roaming", "BurpSuite", "mcp-proxy")
            os.contains("mac") || os.contains("darwin") -> Path.of(home, ".BurpSuite", "mcp-proxy")
            os.contains("linux") || os.contains("unix") -> Path.of(home, ".BurpSuite", "mcp-proxy")
            else -> throw RuntimeException("Unsupported OS: $os")
        }

        return basePath.resolve(PROXY_JAR_NAME)
    }
}