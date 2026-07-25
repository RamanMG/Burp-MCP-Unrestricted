package net.portswigger.mcp

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import java.awt.EventQueue
import kotlin.coroutines.CoroutineContext

object SwingDispatcher : CoroutineDispatcher() {
    override fun dispatch(context: CoroutineContext, block: Runnable) {
        if (EventQueue.isDispatchThread()) {
            block.run()
        } else {
            EventQueue.invokeLater(block)
        }
    }
}

@Suppress("UnusedReceiverParameter")
val Dispatchers.Swing: CoroutineDispatcher
    get() = SwingDispatcher