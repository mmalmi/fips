public protocol FipsBlePlatform: AnyObject {
    var eventSink: HostBleEventSink { get set }

    func submit(_ command: HostBleCommand)

    func close()
}

public final class FipsBleCommandRunner {
    private let platform: FipsBlePlatform

    public init(
        platform: FipsBlePlatform,
        eventSink: @escaping HostBleEventSink = { _ in }
    ) {
        self.platform = platform
        platform.eventSink = eventSink
    }

    public func submit(_ command: HostBleCommand) {
        platform.submit(command)
    }

    public func close() {
        platform.close()
    }
}
