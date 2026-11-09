"""Exercise a built relay and its adjacent cashu-service-mint against a CLN RPC fixture."""
import asyncio
import json
import socket
import sys
import tempfile
from pathlib import Path
from urllib.request import urlopen


async def main(relay):
    helper = relay.with_name("cashu-service-mint")
    assert relay.is_file() and helper.is_file()
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        state = root / "state"
        sock = root / "lightning-rpc"
        config = root / "relay.json"
        network = "regtest"
        node_id = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        waiters = asyncio.Event()
        probes = 0

        async def rpc(reader, writer):
            nonlocal probes
            try:
                while True:
                    req = json.loads(await reader.readuntil(b"\n\n"))
                    if req["method"] == "getinfo":
                        probes += 1
                        data = {"lightning-dir": temp, "network": network, "id": node_id, "alias": "test",
                                "address": [], "blockheight": 1, "color": "000000", "fees_collected_msat": 0,
                                "num_active_channels": 0, "num_inactive_channels": 0, "num_pending_channels": 0,
                                "num_peers": 0, "version": "fixture"}
                    elif req["method"] == "listinvoices":
                        data = {"invoices": []}
                    elif req["method"] == "waitanyinvoice":
                        waiters.set()
                        await reader.read()
                        return
                    else:
                        raise AssertionError(req["method"])
                    writer.write(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": data}).encode() + b"\n\n")
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()

        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            host = f"127.0.0.1:{reserve.getsockname()[1]}"
        url = f"http://{host}"
        cfg = json.loads(Path(__file__).resolve().parents[1].joinpath("service.example.json").read_text())
        cfg.update(state_directory=str(state), transports={"udp": {"bind_addr": "127.0.0.1:0", "advertise_on_nostr": False}})
        cfg["terms"].update(billing="forwarding_data", local_mint={"cln_socket": str(sock)})
        cfg["terms"]["controller"]["mint_url"] = url
        config.write_text(json.dumps(cfg))

        async def command(*args, error=None):
            proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), 20)
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
            if error is None:
                assert proc.returncode == 0, stderr.decode()[-1000:]
            else:
                assert proc.returncode != 0 and error in stderr.decode(), stderr.decode()[-1000:]

        def get(path):
            with urlopen(url + path, timeout=1) as resp:
                return json.load(resp)

        async def ready(proc):
            await asyncio.wait_for(waiters.wait(), 15)
            for _ in range(100):
                if proc.returncode is not None:
                    raise AssertionError("relay exited before readiness")
                try:
                    info = await asyncio.to_thread(get, "/v1/info")
                    if (state / "control.sock").is_socket() and info["nuts"]["5"]["disabled"]:
                        return await asyncio.to_thread(get, "/v1/keysets")
                except OSError:
                    pass
                await asyncio.sleep(.05)
            raise AssertionError("managed service failed readiness")

        await command(relay, "init", config)
        await command(helper, "init", state / "mint", error="fresh directory")
        await command(helper, "serve", state / "mint", sock, host, "redeemable", error="redemption policy")
        server = await asyncio.start_unix_server(rpc, path=sock)
        async with server:
            previous = None
            for attempt in range(2):
                waiters.clear()
                proc = await asyncio.create_subprocess_exec(relay, "run", config)
                try:
                    keys = await ready(proc)
                    assert keys["keysets"] and (previous is None or previous == keys)
                    previous = keys
                    await command(relay, "run", config, error="already has an owner")
                    if attempt == 0:
                        # Keep the relay alive while its child detects an invalid
                        # backend, then let the supervisor reconnect the original node.
                        network = "bitcoin"
                        initial = probes
                        async def replacement_rejected():
                            while probes < initial + 2:
                                await asyncio.sleep(.05)
                        await asyncio.wait_for(replacement_rejected(), 18)
                        waiters.clear()
                        network = "regtest"
                        assert await ready(proc) == keys
                finally:
                    if proc.returncode is None:
                        proc.terminate()
                        await asyncio.wait_for(proc.wait(), 20)
                assert proc.returncode == 0
            network = "bitcoin"
            await command(relay, "run", config, error="Core Lightning network or node identity changed")
        print("Managed mint checks passed: fresh init, fixed policy, readiness, exclusive owner, restart, stable keyset, node binding.")


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]).resolve()))
