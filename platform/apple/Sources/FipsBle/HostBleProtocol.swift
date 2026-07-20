import Foundation

public enum HostBleCommand: Equatable {
    case listen(requestId: UInt64, preferredPsm: UInt16)
    case stopListening
    case startAdvertising(requestId: UInt64, bootstrap: Data)
    case stopAdvertising(requestId: UInt64)
    case startScanning(requestId: UInt64)
    case stopScanning
    case connect(requestId: UInt64, peerToken: String, psm: UInt16)
    case write(requestId: UInt64, connectionId: UInt64, bytes: Data)
    case close(connectionId: UInt64)
}

public enum HostBleEvent: Equatable {
    case listening(requestId: UInt64, psm: UInt16)
    case advertisingStarted(requestId: UInt64)
    case advertisingStopped(requestId: UInt64)
    case scanningStarted(requestId: UInt64)
    case peerDiscovered(peerToken: String, bootstrap: Data)
    case connected(
        requestId: UInt64,
        connectionId: UInt64,
        peerToken: String,
        sendSegmentMtu: UInt16,
        receiveSegmentMtu: UInt16
    )
    case incomingConnection(
        connectionId: UInt64,
        peerToken: String,
        sendSegmentMtu: UInt16,
        receiveSegmentMtu: UInt16
    )
    case bytesReceived(connectionId: UInt64, bytes: Data)
    case writeCompleted(requestId: UInt64)
    case disconnected(connectionId: UInt64, reason: String?)
    case failed(requestId: UInt64, message: String)
}

public typealias HostBleEventSink = (HostBleEvent) -> Void
