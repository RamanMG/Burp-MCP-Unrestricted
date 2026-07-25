package net.portswigger.mcp.config

import java.awt.Desktop
import java.awt.event.ActionEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.font.TextAttribute
import java.net.URI
import javax.swing.AbstractAction
import javax.swing.JLabel
import javax.swing.KeyStroke
import javax.swing.UIManager

class Anchor(text: String, private val url: String) : JLabel(text) {

    init {
        font = font.deriveFont(mapOf(TextAttribute.UNDERLINE to TextAttribute.UNDERLINE_ON))
        foreground = UIManager.getColor("Burp.anchorForeground")
        cursor = java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR)
        isFocusable = true

        val openLinkAction = object : AbstractAction() {
            override fun actionPerformed(e: ActionEvent?) {
                try {
                    if (Desktop.isDesktopSupported()) {
                        Desktop.getDesktop().browse(URI(url))
                    }
                } catch (_: Exception) {
                }
            }
        }

        actionMap.put("pressed", openLinkAction)
        inputMap.put(KeyStroke.getKeyStroke("released SPACE"), "pressed")

        addMouseListener(object : MouseAdapter() {
            override fun mouseEntered(e: MouseEvent) {
                foreground = UIManager.getColor("Burp.anchorHoverForeground")
            }

            override fun mouseExited(e: MouseEvent) {
                foreground = UIManager.getColor("Burp.anchorForeground")
            }

            override fun mouseClicked(e: MouseEvent) {
                openLinkAction.actionPerformed(null)
            }
        })
    }

    override fun updateUI() {
        super.updateUI()
        foreground = UIManager.getColor("Burp.anchorForeground")
    }
}