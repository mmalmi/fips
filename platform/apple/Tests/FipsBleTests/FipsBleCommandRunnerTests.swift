import Foundation
@testable import FipsBle
import XCTest

final class FipsBleCommandRunnerTests: XCTestCase {
    func testRoutesEveryHostCommandWithoutReinterpretingValues() {
        let platform = RecordingPlatform()
        let runner = FipsBleCommandRunner(platform: platform)
        let commands: [HostBleCommand] = [
            .listen(requestId: 1, preferredPsm: 0x85),
            .startAdvertising(requestId: 2, bootstrap: Data([1, 2, 3])),
            .startScanning(requestId: 3),
            .connect(requestId: 4, peerToken: "peer", psm: 0x91),
            .write(requestId: 5, connectionId: 7, bytes: Data([4, 5, 6])),
            .close(connectionId: 7),
            .stopScanning,
            .stopAdvertising(requestId: 6),
            .stopListening,
        ]

        commands.forEach(runner.submit)

        XCTAssertEqual(platform.commands, commands)
    }

    func testForwardsPlatformEventsToRustFacingSink() {
        let platform = RecordingPlatform()
        var events: [HostBleEvent] = []
        _ = FipsBleCommandRunner(platform: platform) { events.append($0) }
        let expected = HostBleEvent.listening(requestId: 9, psm: 0x99)

        platform.eventSink(expected)

        XCTAssertEqual(events, [expected])
    }
}

private final class RecordingPlatform: FipsBlePlatform {
    var eventSink: HostBleEventSink = { _ in }
    var commands: [HostBleCommand] = []

    func submit(_ command: HostBleCommand) {
        commands.append(command)
    }

    func close() {}
}
