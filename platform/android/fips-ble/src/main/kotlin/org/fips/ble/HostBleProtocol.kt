package org.fips.ble

sealed interface HostBleCommand {
    data class Listen(val requestId: Long, val preferredPsm: Int) : HostBleCommand
    data object StopListening : HostBleCommand
    data class StartAdvertising(val requestId: Long, val bootstrap: ByteArray) : HostBleCommand
    data class StopAdvertising(val requestId: Long) : HostBleCommand
    data class StartScanning(val requestId: Long) : HostBleCommand
    data object StopScanning : HostBleCommand
    data class Connect(val requestId: Long, val peerToken: String, val psm: Int) : HostBleCommand
    data class Write(val requestId: Long, val connectionId: Long, val bytes: ByteArray) : HostBleCommand
    data class Close(val connectionId: Long) : HostBleCommand
}

sealed interface HostBleEvent {
    data class Listening(val requestId: Long, val psm: Int) : HostBleEvent
    data class AdvertisingStarted(val requestId: Long) : HostBleEvent
    data class AdvertisingStopped(val requestId: Long) : HostBleEvent
    data class ScanningStarted(val requestId: Long) : HostBleEvent
    data class PeerDiscovered(val peerToken: String, val bootstrap: ByteArray) : HostBleEvent
    data class Connected(
        val requestId: Long,
        val connectionId: Long,
        val peerToken: String,
        val sendSegmentMtu: Int,
        val receiveSegmentMtu: Int,
    ) : HostBleEvent

    data class IncomingConnection(
        val connectionId: Long,
        val peerToken: String,
        val sendSegmentMtu: Int,
        val receiveSegmentMtu: Int,
    ) : HostBleEvent

    data class BytesReceived(val connectionId: Long, val bytes: ByteArray) : HostBleEvent
    data class WriteCompleted(val requestId: Long) : HostBleEvent
    data class Disconnected(val connectionId: Long, val reason: String?) : HostBleEvent
    data class Failed(val requestId: Long, val message: String) : HostBleEvent
}

fun interface HostBleEventSink {
    fun emit(event: HostBleEvent)
}
