package org.fips.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelUuid
import java.io.IOException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private val FIPS_SERVICE_UUID: UUID = UUID.fromString("9c90b792-2cc5-42c0-9f87-c9cc40648f4c")
private val FIPS_BOOTSTRAP_UUID: UUID = UUID.fromString("9c90b793-2cc5-42c0-9f87-c9cc40648f4c")
private const val MAX_PLATFORM_CONNECTIONS = 64
private const val MAX_IO_THREADS = MAX_PLATFORM_CONNECTIONS * 2 + 2

/** Android BLE v2 adapter. L2CAP CoC requires Android API 29 or newer. */
@SuppressLint("MissingPermission")
@Suppress("DEPRECATION")
class AndroidFipsBlePlatform(context: Context) : FipsBlePlatform {
    private val appContext = context.applicationContext
    private val manager = appContext.getSystemService(BluetoothManager::class.java)
    private val adapter: BluetoothAdapter?
        get() = manager?.adapter
    private val stateThread = HandlerThread("fips-ble-state").apply { start() }
    private val state = Handler(stateThread.looper)
    private val io: ExecutorService =
        ThreadPoolExecutor(
            0,
            MAX_IO_THREADS,
            60L,
            TimeUnit.SECONDS,
            SynchronousQueue<Runnable>(),
        )
    private val nextConnectionId = AtomicLong(1)
    private val connections = mutableMapOf<Long, AndroidBleConnection>()
    private val pendingConnectRequests = mutableSetOf<Long>()
    private val pendingConnectSockets = ConcurrentHashMap<Long, BluetoothSocket>()
    private val discoveryGatts = mutableMapOf<String, BluetoothGatt>()
    private val discoveredTokens = BootstrapDiscoveryCache()
    private var eventSink = HostBleEventSink {}
    private var serverSocket: BluetoothServerSocket? = null
    private var gattServer: BluetoothGattServer? = null
    private var bootstrapValue = byteArrayOf()
    private var pendingAdvertiseRequest: Long? = null
    private var scanRequest: Long? = null
    private val closing = AtomicBoolean(false)
    private var closed = false

    override fun setEventSink(sink: HostBleEventSink) {
        state.post { eventSink = sink }
    }

    override fun submit(command: HostBleCommand) {
        state.post {
            if (closed) {
                command.requestIdOrNull()?.let { emit(HostBleEvent.Failed(it, "BLE adapter is closed")) }
                return@post
            }
            try {
                when (command) {
                    is HostBleCommand.Listen -> listen(command)
                    HostBleCommand.StopListening -> stopListening()
                    is HostBleCommand.StartAdvertising -> startAdvertising(command)
                    is HostBleCommand.StopAdvertising -> stopAdvertising(command.requestId)
                    is HostBleCommand.StartScanning -> startScanning(command.requestId)
                    HostBleCommand.StopScanning -> stopScanning()
                    is HostBleCommand.Connect -> connect(command)
                    is HostBleCommand.Write -> write(command)
                    is HostBleCommand.Close -> closeConnection(command.connectionId, null)
                }
            } catch (error: Exception) {
                command.requestIdOrNull()?.let {
                    emit(HostBleEvent.Failed(it, error.bleMessage("BLE command")))
                }
            }
        }
    }

    override fun close() {
        if (!closing.compareAndSet(false, true)) return
        state.post {
            if (closed) return@post
            closed = true
            stopScanning()
            stopAdvertisingWithoutEvent()
            stopListening()
            pendingConnectSockets.values.forEach { runCatching { it.close() } }
            pendingConnectSockets.clear()
            pendingConnectRequests.clear()
            connections.keys.toList().forEach { closeConnection(it, null) }
            io.shutdownNow()
            stateThread.quitSafely()
        }
    }

    private fun listen(command: HostBleCommand.Listen) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            emit(HostBleEvent.Failed(command.requestId, "Android L2CAP CoC requires API 29"))
            return
        }
        if (serverSocket != null) {
            emit(HostBleEvent.Failed(command.requestId, "BLE listener is already running"))
            return
        }
        val bluetooth = adapter
        if (bluetooth == null || !bluetooth.isEnabled) {
            emit(HostBleEvent.Failed(command.requestId, "Bluetooth is unavailable or off"))
            return
        }
        io.execute {
            try {
                val socket = bluetooth.listenUsingInsecureL2capChannel()
                state.post {
                    if (closed || serverSocket != null) {
                        runCatching { socket.close() }
                        return@post
                    }
                    serverSocket = socket
                    emit(HostBleEvent.Listening(command.requestId, socket.psm))
                    acceptConnections(socket)
                }
            } catch (error: Exception) {
                state.post { emit(HostBleEvent.Failed(command.requestId, error.bleMessage("listen"))) }
            }
        }
    }

    private fun acceptConnections(server: BluetoothServerSocket) {
        io.execute {
            while (!closed && serverSocket === server) {
                val socket =
                    try {
                        server.accept()
                    } catch (_: IOException) {
                        break
                    } catch (error: SecurityException) {
                        state.post { stopListening() }
                        break
                    }
                state.post { registerIncoming(socket) }
            }
        }
    }

    private fun registerIncoming(socket: BluetoothSocket) {
        try {
            if (connections.size + pendingConnectRequests.size >= MAX_PLATFORM_CONNECTIONS) {
                runCatching { socket.close() }
                return
            }
            val connection = createConnection(socket) ?: return
            connections[connection.id] = connection
            connection.startReading()
            emit(
                HostBleEvent.IncomingConnection(
                    connection.id,
                    socket.remoteDevice.address,
                    connection.sendMtu,
                    connection.receiveMtu,
                ),
            )
        } catch (_: Exception) {
            runCatching { socket.close() }
        }
    }

    private fun stopListening() {
        val socket = serverSocket
        serverSocket = null
        runCatching { socket?.close() }
    }

    private fun startAdvertising(command: HostBleCommand.StartAdvertising) {
        val bluetooth = adapter
        val advertiser = bluetooth?.bluetoothLeAdvertiser
        if (bluetooth == null || !bluetooth.isEnabled || advertiser == null) {
            emit(HostBleEvent.Failed(command.requestId, "BLE advertising is unavailable"))
            return
        }
        if (pendingAdvertiseRequest != null || gattServer != null) {
            emit(HostBleEvent.Failed(command.requestId, "BLE advertising is already running"))
            return
        }
        bootstrapValue = command.bootstrap.copyOf()
        pendingAdvertiseRequest = command.requestId
        val server = manager?.openGattServer(appContext, gattServerCallback)
        if (server == null) {
            pendingAdvertiseRequest = null
            emit(HostBleEvent.Failed(command.requestId, "Could not open BLE GATT server"))
            return
        }
        gattServer = server
        val service = BluetoothGattService(FIPS_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val characteristic =
            BluetoothGattCharacteristic(
                FIPS_BOOTSTRAP_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ,
            )
        characteristic.value = bootstrapValue
        service.addCharacteristic(characteristic)
        if (!server.addService(service)) {
            failAdvertising(command.requestId, "Could not add BLE bootstrap service")
        }
    }

    private val gattServerCallback =
        object : BluetoothGattServerCallback() {
            override fun onServiceAdded(status: Int, service: BluetoothGattService) {
                state.post {
                    val requestId = pendingAdvertiseRequest ?: return@post
                    if (status != BluetoothGatt.GATT_SUCCESS || service.uuid != FIPS_SERVICE_UUID) {
                        failAdvertising(requestId, "Could not publish BLE bootstrap service ($status)")
                        return@post
                    }
                    beginAdvertising(requestId)
                }
            }

            override fun onCharacteristicReadRequest(
                device: BluetoothDevice,
                requestId: Int,
                offset: Int,
                characteristic: BluetoothGattCharacteristic,
            ) {
                state.post {
                    val server = gattServer ?: return@post
                    if (characteristic.uuid != FIPS_BOOTSTRAP_UUID || offset > bootstrapValue.size) {
                        server.sendResponse(
                            device,
                            requestId,
                            BluetoothGatt.GATT_INVALID_OFFSET,
                            offset,
                            null,
                        )
                    } else {
                        server.sendResponse(
                            device,
                            requestId,
                            BluetoothGatt.GATT_SUCCESS,
                            offset,
                            bootstrapValue.copyOfRange(offset, bootstrapValue.size),
                        )
                    }
                }
            }
        }

    private fun beginAdvertising(requestId: Long) {
        val advertiser = adapter?.bluetoothLeAdvertiser
        if (advertiser == null) {
            failAdvertising(requestId, "BLE advertising became unavailable")
            return
        }
        val settings =
            AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
                .setConnectable(true)
                .setTimeout(0)
                .build()
        val data =
            AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(ParcelUuid(FIPS_SERVICE_UUID))
                .build()
        try {
            advertiser.startAdvertising(settings, data, advertiseCallback)
        } catch (error: Exception) {
            failAdvertising(requestId, error.bleMessage("advertise"))
        }
    }

    private val advertiseCallback =
        object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
                state.post {
                    pendingAdvertiseRequest?.let {
                        pendingAdvertiseRequest = null
                        emit(HostBleEvent.AdvertisingStarted(it))
                    }
                }
            }

            override fun onStartFailure(errorCode: Int) {
                state.post {
                    val requestId = pendingAdvertiseRequest ?: return@post
                    failAdvertising(requestId, "BLE advertising failed ($errorCode)")
                }
            }
        }

    private fun failAdvertising(requestId: Long, message: String) {
        pendingAdvertiseRequest = null
        stopAdvertisingWithoutEvent()
        emit(HostBleEvent.Failed(requestId, message))
    }

    private fun stopAdvertising(requestId: Long) {
        stopAdvertisingWithoutEvent()
        emit(HostBleEvent.AdvertisingStopped(requestId))
    }

    private fun stopAdvertisingWithoutEvent() {
        runCatching { adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
        gattServer?.clearServices()
        gattServer?.close()
        gattServer = null
        pendingAdvertiseRequest = null
        bootstrapValue = byteArrayOf()
    }

    private fun startScanning(requestId: Long) {
        val scanner = adapter?.bluetoothLeScanner
        if (scanner == null) {
            emit(HostBleEvent.Failed(requestId, "BLE scanning is unavailable"))
            return
        }
        if (scanRequest != null) {
            emit(HostBleEvent.Failed(requestId, "BLE scanning is already running"))
            return
        }
        discoveredTokens.clear()
        scanRequest = requestId
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(FIPS_SERVICE_UUID)).build()
        val settings =
            ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .build()
        try {
            scanner.startScan(listOf(filter), settings, scanCallback)
            emit(HostBleEvent.ScanningStarted(requestId))
        } catch (error: Exception) {
            scanRequest = null
            emit(HostBleEvent.Failed(requestId, error.bleMessage("scan")))
        }
    }

    private val scanCallback =
        object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                state.post { discoverBootstrap(result.device) }
            }

            override fun onBatchScanResults(results: MutableList<ScanResult>) {
                state.post { results.forEach { discoverBootstrap(it.device) } }
            }

            override fun onScanFailed(errorCode: Int) {
                state.post {
                    val requestId = scanRequest ?: return@post
                    stopScanning()
                    emit(HostBleEvent.Failed(requestId, "BLE scan failed ($errorCode)"))
                }
            }
        }

    private fun discoverBootstrap(device: BluetoothDevice) {
        if (scanRequest == null) return
        try {
            val token = device.address
            if (!discoveredTokens.begin(token)) return
            val callback = BootstrapGattCallback(token)
            val gatt =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    device.connectGatt(appContext, false, callback, BluetoothDevice.TRANSPORT_LE, 0, state)
                } else {
                    device.connectGatt(appContext, false, callback, BluetoothDevice.TRANSPORT_LE)
                }
            discoveryGatts[token] = gatt
        } catch (_: Exception) {
            runCatching { discoveredTokens.invalidate(device.address) }
        }
    }

    private inner class BootstrapGattCallback(private val token: String) : BluetoothGattCallback() {
        private val finished = AtomicBoolean(false)

        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED) {
                if (!gatt.discoverServices()) finish(gatt, null)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED || status != BluetoothGatt.GATT_SUCCESS) {
                finish(gatt, null)
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                finish(gatt, null)
                return
            }
            val characteristic = gatt.getService(FIPS_SERVICE_UUID)?.getCharacteristic(FIPS_BOOTSTRAP_UUID)
            if (characteristic == null || !gatt.readCharacteristic(characteristic)) finish(gatt, null)
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int,
        ) {
            finishRead(gatt, characteristic, value, status)
        }

        @Deprecated("Used on Android 12 and older")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            finishRead(gatt, characteristic, characteristic.value ?: byteArrayOf(), status)
        }

        private fun finishRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int,
        ) {
            val bytes =
                value.takeIf {
                    status == BluetoothGatt.GATT_SUCCESS && characteristic.uuid == FIPS_BOOTSTRAP_UUID
                }
            finish(gatt, bytes)
        }

        private fun finish(gatt: BluetoothGatt, bootstrap: ByteArray?) {
            if (!finished.compareAndSet(false, true)) return
            state.post {
                discoveryGatts.remove(token)
                if (bootstrap == null || scanRequest == null) {
                    discoveredTokens.invalidate(token)
                } else {
                    discoveredTokens.complete(token)
                    emit(HostBleEvent.PeerDiscovered(token, bootstrap.copyOf()))
                }
                gatt.disconnect()
                gatt.close()
            }
        }
    }

    private fun stopScanning() {
        runCatching { adapter?.bluetoothLeScanner?.stopScan(scanCallback) }
        scanRequest = null
        discoveryGatts.values.forEach {
            it.disconnect()
            it.close()
        }
        discoveryGatts.clear()
        discoveredTokens.clear()
    }

    private fun connect(command: HostBleCommand.Connect) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            emit(HostBleEvent.Failed(command.requestId, "Android L2CAP CoC requires API 29"))
            return
        }
        val bluetooth = adapter
        if (bluetooth == null || !bluetooth.isEnabled) {
            emit(HostBleEvent.Failed(command.requestId, "Bluetooth is unavailable or off"))
            return
        }
        if (connections.size + pendingConnectRequests.size >= MAX_PLATFORM_CONNECTIONS) {
            emit(HostBleEvent.Failed(command.requestId, "BLE connection limit reached"))
            return
        }
        pendingConnectRequests.add(command.requestId)
        try {
            io.execute {
                var socket: BluetoothSocket? = null
                try {
                    if (closing.get()) return@execute
                    val device = bluetooth.getRemoteDevice(command.peerToken)
                    socket = device.createInsecureL2capChannel(command.psm)
                    pendingConnectSockets[command.requestId] = socket
                    if (closing.get()) {
                        pendingConnectSockets.remove(command.requestId)
                        runCatching { socket?.close() }
                        return@execute
                    }
                    socket.connect()
                    pendingConnectSockets.remove(command.requestId)
                    val connectedSocket = socket
                    state.post {
                        pendingConnectRequests.remove(command.requestId)
                        registerOutgoing(command, connectedSocket)
                    }
                    socket = null
                } catch (error: Exception) {
                    pendingConnectSockets.remove(command.requestId)
                    runCatching { socket?.close() }
                    state.post {
                        pendingConnectRequests.remove(command.requestId)
                        discoveredTokens.invalidate(command.peerToken)
                        emit(HostBleEvent.Failed(command.requestId, error.bleMessage("connect")))
                        runCatching { bluetooth.getRemoteDevice(command.peerToken) }
                            .onSuccess(::discoverBootstrap)
                    }
                }
            }
        } catch (error: Exception) {
            pendingConnectRequests.remove(command.requestId)
            throw error
        }
    }

    private fun registerOutgoing(command: HostBleCommand.Connect, socket: BluetoothSocket) {
        if (closed) {
            runCatching { socket.close() }
            return
        }
        val connection = createConnection(socket)
        if (connection == null) {
            emit(HostBleEvent.Failed(command.requestId, "BLE connection reported an invalid MTU"))
            return
        }
        connections[connection.id] = connection
        connection.startReading()
        emit(
            HostBleEvent.Connected(
                command.requestId,
                connection.id,
                command.peerToken,
                connection.sendMtu,
                connection.receiveMtu,
            ),
        )
    }

    private fun createConnection(socket: BluetoothSocket): AndroidBleConnection? {
        val sendMtu = socket.maxTransmitPacketSize
        val receiveMtu = socket.maxReceivePacketSize
        if (sendMtu <= 0 || receiveMtu <= 0) {
            runCatching { socket.close() }
            return null
        }
        return AndroidBleConnection(nextConnectionId.getAndIncrement(), socket, sendMtu, receiveMtu)
    }

    private fun write(command: HostBleCommand.Write) {
        val connection = connections[command.connectionId]
        if (connection == null) {
            emit(HostBleEvent.Failed(command.requestId, "Unknown BLE connection"))
            return
        }
        connection.write(command.requestId, command.bytes.copyOf())
    }

    private fun closeConnection(connectionId: Long, reason: String?) {
        val connection = connections.remove(connectionId) ?: return
        connection.close()
        emit(HostBleEvent.Disconnected(connectionId, reason))
    }

    private inner class AndroidBleConnection(
        val id: Long,
        private val socket: BluetoothSocket,
        val sendMtu: Int,
        val receiveMtu: Int,
    ) {
        private val stopped = AtomicBoolean(false)
        private val writer = Executors.newSingleThreadExecutor()

        fun startReading() {
            io.execute {
                val buffer = ByteArray(receiveMtu)
                try {
                    val input = socket.inputStream
                    while (!stopped.get()) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (count > 0) {
                            emitFromAnyThread(HostBleEvent.BytesReceived(id, buffer.copyOf(count)))
                        }
                    }
                    state.post { closeConnection(id, null) }
                } catch (error: Exception) {
                    state.post { closeConnection(id, error.bleMessage("read")) }
                }
            }
        }

        fun write(requestId: Long, bytes: ByteArray) {
            writer.execute {
                try {
                    if (bytes.isEmpty() || bytes.size > sendMtu) {
                        throw IOException("invalid BLE write length ${bytes.size} for MTU $sendMtu")
                    }
                    socket.outputStream.write(bytes)
                    socket.outputStream.flush()
                    emitFromAnyThread(HostBleEvent.WriteCompleted(requestId))
                } catch (error: Exception) {
                    emitFromAnyThread(HostBleEvent.Failed(requestId, error.bleMessage("write")))
                    state.post { closeConnection(id, error.bleMessage("write")) }
                }
            }
        }

        fun close() {
            if (!stopped.compareAndSet(false, true)) return
            runCatching { socket.close() }
            writer.shutdownNow()
        }
    }

    private fun emitFromAnyThread(event: HostBleEvent) {
        state.post { emit(event) }
    }

    private fun emit(event: HostBleEvent) {
        if (!closed || event is HostBleEvent.Disconnected) eventSink.emit(event)
    }
}

private fun HostBleCommand.requestIdOrNull(): Long? =
    when (this) {
        is HostBleCommand.Listen -> requestId
        is HostBleCommand.StartAdvertising -> requestId
        is HostBleCommand.StopAdvertising -> requestId
        is HostBleCommand.StartScanning -> requestId
        is HostBleCommand.Connect -> requestId
        is HostBleCommand.Write -> requestId
        is HostBleCommand.Close, HostBleCommand.StopListening, HostBleCommand.StopScanning -> null
    }

private fun Exception.bleMessage(operation: String): String =
    "$operation failed: ${message ?: javaClass.simpleName}"

class FipsBleAdapter(
    context: Context,
    eventSink: HostBleEventSink,
) : AutoCloseable {
    private val runner = FipsBleCommandRunner(AndroidFipsBlePlatform(context), eventSink)

    fun submit(command: HostBleCommand) = runner.submit(command)

    override fun close() = runner.close()
}
