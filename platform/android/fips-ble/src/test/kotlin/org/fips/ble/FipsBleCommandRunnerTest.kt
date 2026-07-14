package org.fips.ble

import org.junit.Assert.assertEquals
import org.junit.Test

class FipsBleCommandRunnerTest {
    @Test
    fun routesEveryHostCommandWithoutReinterpretingIdsOrBytes() {
        val platform = RecordingPlatform()
        val runner = FipsBleCommandRunner(platform)
        val commands =
            listOf(
                HostBleCommand.Listen(1, 0x85),
                HostBleCommand.StartAdvertising(2, byteArrayOf(1, 2, 3)),
                HostBleCommand.StartScanning(3),
                HostBleCommand.Connect(4, "AA:BB:CC:DD:EE:FF", 0x91),
                HostBleCommand.Write(5, 7, byteArrayOf(4, 5, 6)),
                HostBleCommand.Close(7),
                HostBleCommand.StopScanning,
                HostBleCommand.StopAdvertising(6),
                HostBleCommand.StopListening,
            )

        commands.forEach(runner::submit)

        assertEquals(commands, platform.commands)
    }

    @Test
    fun forwardsPlatformEventsToTheRustFacingSink() {
        val events = mutableListOf<HostBleEvent>()
        val platform = RecordingPlatform()
        FipsBleCommandRunner(platform) { events += it }
        val expected = HostBleEvent.Listening(9, 0x99)

        platform.emit(expected)

        assertEquals(listOf(expected), events)
    }
}

private class RecordingPlatform : FipsBlePlatform {
    val commands = mutableListOf<HostBleCommand>()
    private var eventSink = HostBleEventSink {}

    override fun setEventSink(sink: HostBleEventSink) {
        eventSink = sink
    }

    override fun submit(command: HostBleCommand) {
        commands += command
    }

    fun emit(event: HostBleEvent) {
        eventSink.emit(event)
    }
}
