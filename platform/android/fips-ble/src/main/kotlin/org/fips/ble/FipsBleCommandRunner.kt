package org.fips.ble

interface FipsBlePlatform : AutoCloseable {
    fun setEventSink(sink: HostBleEventSink)

    fun submit(command: HostBleCommand)

    override fun close() = Unit
}

class FipsBleCommandRunner(
    private val platform: FipsBlePlatform,
    eventSink: HostBleEventSink = HostBleEventSink {},
) : AutoCloseable {
    init {
        platform.setEventSink(eventSink)
    }

    fun submit(command: HostBleCommand) {
        platform.submit(command)
    }

    override fun close() {
        platform.close()
    }
}
