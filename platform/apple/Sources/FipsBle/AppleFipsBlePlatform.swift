import CoreBluetooth
import Foundation

private let fipsServiceUuid = CBUUID(string: "9c90b792-2cc5-42c0-9f87-c9cc40648f4c")
private let fipsBootstrapUuid = CBUUID(string: "9c90b793-2cc5-42c0-9f87-c9cc40648f4c")
private let appleSegmentMtu: UInt16 = 512
private let maxPlatformConnections = 64
private let maxPendingBootstrapDiscoveries = 64

public final class AppleFipsBlePlatform: NSObject, FipsBlePlatform {
    public var eventSink: HostBleEventSink = { _ in }

    private var central: CBCentralManager!
    private var peripheralManager: CBPeripheralManager!
    private var deferredCommands: [HostBleCommand] = []
    private var listenRequest: UInt64?
    private var publishedPsm: CBL2CAPPSM?
    private var pendingAdvertising: (requestId: UInt64, service: CBMutableService)?
    private var advertisedService: CBMutableService?
    private var scanRequest: UInt64?
    private var peripherals: [UUID: CBPeripheral] = [:]
    private var discoveryPending: Set<UUID> = []
    private var connectRequests: [UUID: (requestId: UInt64, psm: UInt16)] = [:]
    private var activeOutgoingPeers: Set<UUID> = []
    private var nextConnectionId: UInt64 = 1
    private var connections: [UInt64: AppleBleConnection] = [:]
    private var isClosed = false

    public override init() {
        super.init()
        onMainSync {
            central = CBCentralManager(delegate: self, queue: .main)
            peripheralManager = CBPeripheralManager(delegate: self, queue: .main)
        }
    }

    public func submit(_ command: HostBleCommand) {
        onMain { [weak self] in self?.handle(command) }
    }

    public func close() {
        onMain { [weak self] in self?.closeOnMain() }
    }

    private func handle(_ command: HostBleCommand) {
        guard !isClosed else {
            if let requestId = command.requestId {
                emit(.failed(requestId: requestId, message: "BLE adapter is closed"))
            }
            return
        }
        if shouldDefer(command) {
            if deferredCommands.count < 32 {
                deferredCommands.append(command)
            } else if let requestId = command.requestId {
                emit(.failed(requestId: requestId, message: "BLE state queue is full"))
            }
            return
        }

        switch command {
        case let .listen(requestId, _):
            startListening(requestId: requestId)
        case .stopListening:
            stopListening()
        case let .startAdvertising(requestId, bootstrap):
            startAdvertising(requestId: requestId, bootstrap: bootstrap)
        case let .stopAdvertising(requestId):
            stopAdvertising(requestId: requestId)
        case let .startScanning(requestId):
            startScanning(requestId: requestId)
        case .stopScanning:
            stopScanning()
        case let .connect(requestId, peerToken, psm):
            connect(requestId: requestId, peerToken: peerToken, psm: psm)
        case let .write(requestId, connectionId, bytes):
            write(requestId: requestId, connectionId: connectionId, bytes: bytes)
        case let .close(connectionId):
            connections[connectionId]?.close(reason: nil)
        }
    }

    private func shouldDefer(_ command: HostBleCommand) -> Bool {
        switch command {
        case .listen, .startAdvertising:
            return peripheralManager.state == .unknown || peripheralManager.state == .resetting
        case .startScanning, .connect:
            return central.state == .unknown || central.state == .resetting
        default:
            return false
        }
    }

    private func replayDeferredCommands() {
        let ready = deferredCommands.filter { !shouldDefer($0) }
        deferredCommands.removeAll { !shouldDefer($0) }
        ready.forEach(handle)
    }

    private func startListening(requestId: UInt64) {
        guard peripheralManager.state == .poweredOn else {
            emit(.failed(requestId: requestId, message: peripheralStateMessage()))
            return
        }
        guard listenRequest == nil, publishedPsm == nil else {
            emit(.failed(requestId: requestId, message: "BLE listener is already running"))
            return
        }
        listenRequest = requestId
        peripheralManager.publishL2CAPChannel(withEncryption: false)
    }

    private func stopListening() {
        if let psm = publishedPsm {
            peripheralManager.unpublishL2CAPChannel(psm)
        }
        publishedPsm = nil
        listenRequest = nil
    }

    private func startAdvertising(requestId: UInt64, bootstrap: Data) {
        guard peripheralManager.state == .poweredOn else {
            emit(.failed(requestId: requestId, message: peripheralStateMessage()))
            return
        }
        guard pendingAdvertising == nil, advertisedService == nil else {
            emit(.failed(requestId: requestId, message: "BLE advertising is already running"))
            return
        }
        let characteristic = CBMutableCharacteristic(
            type: fipsBootstrapUuid,
            properties: [.read],
            value: bootstrap,
            permissions: [.readable]
        )
        let service = CBMutableService(type: fipsServiceUuid, primary: true)
        service.characteristics = [characteristic]
        pendingAdvertising = (requestId, service)
        peripheralManager.add(service)
    }

    private func stopAdvertising(requestId: UInt64) {
        peripheralManager.stopAdvertising()
        if let service = pendingAdvertising?.service ?? advertisedService {
            peripheralManager.remove(service)
        }
        pendingAdvertising = nil
        advertisedService = nil
        emit(.advertisingStopped(requestId: requestId))
    }

    private func startScanning(requestId: UInt64) {
        guard central.state == .poweredOn else {
            emit(.failed(requestId: requestId, message: centralStateMessage()))
            return
        }
        guard scanRequest == nil else {
            emit(.failed(requestId: requestId, message: "BLE scanning is already running"))
            return
        }
        scanRequest = requestId
        discoveryPending.removeAll()
        central.scanForPeripherals(withServices: [fipsServiceUuid], options: [
            CBCentralManagerScanOptionAllowDuplicatesKey: false,
        ])
        emit(.scanningStarted(requestId: requestId))
    }

    private func stopScanning() {
        central.stopScan()
        scanRequest = nil
        for (identifier, peripheral) in peripherals {
            if connectRequests[identifier] == nil, !activeOutgoingPeers.contains(identifier) {
                central.cancelPeripheralConnection(peripheral)
            }
        }
        discoveryPending.removeAll()
    }

    private func connect(requestId: UInt64, peerToken: String, psm: UInt16) {
        guard central.state == .poweredOn else {
            emit(.failed(requestId: requestId, message: centralStateMessage()))
            return
        }
        guard let identifier = UUID(uuidString: peerToken) else {
            emit(.failed(requestId: requestId, message: "Invalid Apple BLE peer token"))
            return
        }
        let peripheral = peripherals[identifier] ?? central.retrievePeripherals(withIdentifiers: [identifier]).first
        guard let peripheral else {
            emit(.failed(requestId: requestId, message: "Apple BLE peer is no longer available"))
            return
        }
        peripherals[identifier] = peripheral
        peripheral.delegate = self
        connectRequests[identifier] = (requestId, psm)
        if peripheral.state == .connected {
            peripheral.openL2CAPChannel(CBL2CAPPSM(psm))
        } else {
            central.connect(peripheral)
        }
    }

    private func write(requestId: UInt64, connectionId: UInt64, bytes: Data) {
        guard let connection = connections[connectionId] else {
            emit(.failed(requestId: requestId, message: "Unknown BLE connection"))
            return
        }
        connection.write(requestId: requestId, bytes: bytes)
    }

    private func register(
        channel: CBL2CAPChannel,
        outgoingRequest: UInt64?
    ) {
        guard connections.count < maxPlatformConnections else {
            channel.inputStream.close()
            channel.outputStream.close()
            if let requestId = outgoingRequest {
                emit(.failed(requestId: requestId, message: "BLE connection limit reached"))
            }
            return
        }
        let connectionId = nextConnectionId
        nextConnectionId &+= 1
        let peerIdentifier = channel.peer.identifier
        let isOutgoing = outgoingRequest != nil
        if isOutgoing {
            activeOutgoingPeers.insert(peerIdentifier)
        }
        let connection = AppleBleConnection(
            id: connectionId,
            channel: channel,
            eventSink: { [weak self] event in self?.emit(event) },
            closed: { [weak self] id, reason in
                guard let self else { return }
                connections.removeValue(forKey: id)
                if isOutgoing {
                    activeOutgoingPeers.remove(peerIdentifier)
                    if let peripheral = peripherals[peerIdentifier] {
                        central.cancelPeripheralConnection(peripheral)
                    }
                }
                emit(.disconnected(connectionId: id, reason: reason))
            }
        )
        connections[connectionId] = connection
        connection.open()
        let token = channel.peer.identifier.uuidString
        if let requestId = outgoingRequest {
            emit(.connected(
                requestId: requestId,
                connectionId: connectionId,
                peerToken: token,
                sendSegmentMtu: appleSegmentMtu,
                receiveSegmentMtu: appleSegmentMtu
            ))
        } else {
            emit(.incomingConnection(
                connectionId: connectionId,
                peerToken: token,
                sendSegmentMtu: appleSegmentMtu,
                receiveSegmentMtu: appleSegmentMtu
            ))
        }
    }

    private func failDiscovery(_ peripheral: CBPeripheral) {
        discoveryPending.remove(peripheral.identifier)
        if connectRequests[peripheral.identifier] == nil {
            central.cancelPeripheralConnection(peripheral)
        }
    }

    private func discoverBootstrap(_ peripheral: CBPeripheral) {
        guard scanRequest != nil else { return }
        let identifier = peripheral.identifier
        guard !discoveryPending.contains(identifier),
              discoveryPending.count < maxPendingBootstrapDiscoveries
        else { return }
        peripherals[identifier] = peripheral
        peripheral.delegate = self
        discoveryPending.insert(identifier)
        if peripheral.state == .connected {
            peripheral.discoverServices([fipsServiceUuid])
        } else {
            central.connect(peripheral)
        }
    }

    private func closeOnMain() {
        guard !isClosed else { return }
        isClosed = true
        deferredCommands.removeAll()
        stopScanning()
        peripheralManager.stopAdvertising()
        peripheralManager.removeAllServices()
        stopListening()
        for peripheral in peripherals.values where peripheral.state != .disconnected {
            central.cancelPeripheralConnection(peripheral)
        }
        connections.values.forEach { $0.close(reason: nil) }
        connections.removeAll()
        connectRequests.removeAll()
        activeOutgoingPeers.removeAll()
        peripherals.removeAll()
    }

    private func emit(_ event: HostBleEvent) {
        eventSink(event)
    }

    private func peripheralStateMessage() -> String {
        switch peripheralManager.state {
        case .poweredOff: return "Bluetooth is off"
        case .unauthorized: return "Bluetooth access is not allowed"
        case .unsupported: return "Bluetooth LE is unavailable"
        default: return "Bluetooth is not ready"
        }
    }

    private func centralStateMessage() -> String {
        switch central.state {
        case .poweredOff: return "Bluetooth is off"
        case .unauthorized: return "Bluetooth access is not allowed"
        case .unsupported: return "Bluetooth LE is unavailable"
        default: return "Bluetooth is not ready"
        }
    }
}

extension AppleFipsBlePlatform: CBPeripheralManagerDelegate {
    public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        replayDeferredCommands()
    }

    public func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didPublishL2CAPChannel psm: CBL2CAPPSM,
        error: Error?
    ) {
        guard let requestId = listenRequest else {
            if error == nil { peripheral.unpublishL2CAPChannel(psm) }
            return
        }
        listenRequest = nil
        if let error {
            emit(.failed(requestId: requestId, message: "BLE listen failed: \(error.localizedDescription)"))
        } else {
            publishedPsm = psm
            emit(.listening(requestId: requestId, psm: UInt16(psm)))
        }
    }

    public func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didAdd service: CBService,
        error: Error?
    ) {
        guard let pending = pendingAdvertising, pending.service.uuid == service.uuid else { return }
        if let error {
            pendingAdvertising = nil
            peripheral.remove(pending.service)
            emit(.failed(
                requestId: pending.requestId,
                message: "BLE bootstrap service failed: \(error.localizedDescription)"
            ))
        } else {
            peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [fipsServiceUuid]])
        }
    }

    public func peripheralManagerDidStartAdvertising(
        _ peripheral: CBPeripheralManager,
        error: Error?
    ) {
        guard let pending = pendingAdvertising else { return }
        pendingAdvertising = nil
        if let error {
            peripheral.remove(pending.service)
            emit(.failed(
                requestId: pending.requestId,
                message: "BLE advertising failed: \(error.localizedDescription)"
            ))
        } else {
            advertisedService = pending.service
            emit(.advertisingStarted(requestId: pending.requestId))
        }
    }

    public func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didOpen channel: CBL2CAPChannel?,
        error: Error?
    ) {
        guard let channel, error == nil else { return }
        register(channel: channel, outgoingRequest: nil)
    }
}

extension AppleFipsBlePlatform: CBCentralManagerDelegate {
    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        replayDeferredCommands()
    }

    public func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        discoverBootstrap(peripheral)
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.delegate = self
        if discoveryPending.contains(peripheral.identifier) {
            peripheral.discoverServices([fipsServiceUuid])
        }
        if let request = connectRequests[peripheral.identifier] {
            peripheral.openL2CAPChannel(CBL2CAPPSM(request.psm))
        }
    }

    public func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: Error?
    ) {
        failDiscovery(peripheral)
        if let request = connectRequests.removeValue(forKey: peripheral.identifier) {
            emit(.failed(
                requestId: request.requestId,
                message: "BLE connect failed: \(error?.localizedDescription ?? "unknown error")"
            ))
        }
    }

    public func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: Error?
    ) {
        discoveryPending.remove(peripheral.identifier)
        if let request = connectRequests.removeValue(forKey: peripheral.identifier) {
            emit(.failed(
                requestId: request.requestId,
                message: "BLE disconnected before L2CAP opened: \(error?.localizedDescription ?? "peer closed")"
            ))
        }
    }
}

extension AppleFipsBlePlatform: CBPeripheralDelegate {
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil,
              let service = peripheral.services?.first(where: { $0.uuid == fipsServiceUuid })
        else {
            failDiscovery(peripheral)
            return
        }
        peripheral.discoverCharacteristics([fipsBootstrapUuid], for: service)
    }

    public func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        guard error == nil,
              let characteristic = service.characteristics?.first(where: { $0.uuid == fipsBootstrapUuid })
        else {
            failDiscovery(peripheral)
            return
        }
        peripheral.readValue(for: characteristic)
    }

    public func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard discoveryPending.remove(peripheral.identifier) != nil else { return }
        if error == nil, let value = characteristic.value, characteristic.uuid == fipsBootstrapUuid {
            emit(.peerDiscovered(peerToken: peripheral.identifier.uuidString, bootstrap: value))
        }
    }

    public func peripheral(
        _ peripheral: CBPeripheral,
        didOpen channel: CBL2CAPChannel?,
        error: Error?
    ) {
        guard let request = connectRequests.removeValue(forKey: peripheral.identifier) else {
            channel?.inputStream.close()
            channel?.outputStream.close()
            return
        }
        guard let channel, error == nil else {
            emit(.failed(
                requestId: request.requestId,
                message: "BLE L2CAP open failed: \(error?.localizedDescription ?? "unknown error")"
            ))
            discoverBootstrap(peripheral)
            return
        }
        register(channel: channel, outgoingRequest: request.requestId)
    }
}

private final class AppleBleConnection: NSObject, StreamDelegate {
    let id: UInt64
    private let channel: CBL2CAPChannel
    private let eventSink: HostBleEventSink
    private let closedSink: (UInt64, String?) -> Void
    private var writes: [PendingWrite] = []
    private var closed = false

    init(
        id: UInt64,
        channel: CBL2CAPChannel,
        eventSink: @escaping HostBleEventSink,
        closed: @escaping (UInt64, String?) -> Void
    ) {
        self.id = id
        self.channel = channel
        self.eventSink = eventSink
        closedSink = closed
    }

    func open() {
        channel.inputStream.delegate = self
        channel.outputStream.delegate = self
        channel.inputStream.schedule(in: .main, forMode: .default)
        channel.outputStream.schedule(in: .main, forMode: .default)
        channel.inputStream.open()
        channel.outputStream.open()
    }

    func write(requestId: UInt64, bytes: Data) {
        guard !closed else {
            eventSink(.failed(requestId: requestId, message: "BLE connection is closed"))
            return
        }
        guard !bytes.isEmpty, bytes.count <= Int(appleSegmentMtu) else {
            eventSink(.failed(requestId: requestId, message: "BLE write exceeds the Apple segment limit"))
            return
        }
        writes.append(PendingWrite(requestId: requestId, bytes: bytes, offset: 0))
        drainWrites()
    }

    func close(reason: String?) {
        guard !closed else { return }
        closed = true
        channel.inputStream.remove(from: .main, forMode: .default)
        channel.outputStream.remove(from: .main, forMode: .default)
        channel.inputStream.close()
        channel.outputStream.close()
        for write in writes {
            eventSink(.failed(requestId: write.requestId, message: reason ?? "BLE connection closed"))
        }
        writes.removeAll()
        closedSink(id, reason)
    }

    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        if eventCode.contains(.hasBytesAvailable) {
            readAvailableBytes()
        }
        if eventCode.contains(.hasSpaceAvailable) || eventCode.contains(.openCompleted) {
            drainWrites()
        }
        if eventCode.contains(.errorOccurred) {
            close(reason: aStream.streamError?.localizedDescription ?? "BLE stream failed")
        } else if eventCode.contains(.endEncountered) {
            close(reason: nil)
        }
    }

    private func readAvailableBytes() {
        var buffer = [UInt8](repeating: 0, count: Int(appleSegmentMtu))
        while channel.inputStream.hasBytesAvailable {
            let count = channel.inputStream.read(&buffer, maxLength: buffer.count)
            if count > 0 {
                eventSink(.bytesReceived(connectionId: id, bytes: Data(buffer[..<count])))
            } else if count < 0 {
                close(reason: channel.inputStream.streamError?.localizedDescription ?? "BLE read failed")
                return
            } else {
                break
            }
        }
    }

    private func drainWrites() {
        guard !closed, channel.outputStream.hasSpaceAvailable else { return }
        while !writes.isEmpty, channel.outputStream.hasSpaceAvailable {
            var write = writes[0]
            let count = write.bytes.withUnsafeBytes { rawBuffer -> Int in
                guard let base = rawBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return channel.outputStream.write(
                    base.advanced(by: write.offset),
                    maxLength: write.bytes.count - write.offset
                )
            }
            if count < 0 {
                close(reason: channel.outputStream.streamError?.localizedDescription ?? "BLE write failed")
                return
            }
            if count == 0 { return }
            write.offset += count
            if write.offset == write.bytes.count {
                writes.removeFirst()
                eventSink(.writeCompleted(requestId: write.requestId))
            } else {
                writes[0] = write
            }
        }
    }
}

private struct PendingWrite {
    let requestId: UInt64
    let bytes: Data
    var offset: Int
}

private extension HostBleCommand {
    var requestId: UInt64? {
        switch self {
        case let .listen(requestId, _),
             let .startAdvertising(requestId, _),
             let .stopAdvertising(requestId),
             let .startScanning(requestId),
             let .connect(requestId, _, _),
             let .write(requestId, _, _):
            return requestId
        case .stopListening, .stopScanning, .close:
            return nil
        }
    }
}

private func onMain(_ body: @escaping () -> Void) {
    if Thread.isMainThread {
        body()
    } else {
        DispatchQueue.main.async(execute: body)
    }
}

private func onMainSync(_ body: () -> Void) {
    if Thread.isMainThread {
        body()
    } else {
        DispatchQueue.main.sync(execute: body)
    }
}

public final class FipsBleAdapter {
    private let runner: FipsBleCommandRunner

    public init(eventSink: @escaping HostBleEventSink) {
        runner = FipsBleCommandRunner(platform: AppleFipsBlePlatform(), eventSink: eventSink)
    }

    public func submit(_ command: HostBleCommand) {
        runner.submit(command)
    }

    public func close() {
        runner.close()
    }
}
