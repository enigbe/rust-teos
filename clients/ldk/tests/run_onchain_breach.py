#!/usr/bin/env python3
"""Run legacy and anchor breach tests with isolated regtest services."""

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[3]


def free_ports(count):
    # Hold every socket until all ports have been selected so they are distinct.
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--teosd", type=Path, default=ROOT / "target/debug/teosd")
    args = parser.parse_args()
    teosd = args.teosd.resolve()
    if not teosd.is_file():
        parser.error("build teosd first: cargo build -p teos --bin teosd --locked")

    test_command = [
        "cargo", "test", "-p", "ldk-watchtower-client", "--locked",
        "--features", "integration-tests", "--test", "onchain_breach",
    ]
    print("Compiling the on-chain test before starting services.", flush=True)
    subprocess.run([*test_command, "--no-run"], cwd=ROOT, check=True)

    processes = []
    with tempfile.TemporaryDirectory(prefix="teos-onchain-breach-") as directory:
        work = Path(directory)
        bitcoin_dir, tower_dir = work / "bitcoin", work / "tower"
        bitcoin_dir.mkdir()
        tower_dir.mkdir()
        rpc_port, api_port, admin_port, internal_port = free_ports(4)
        (tower_dir / "teos.toml").write_text(
            f"polling_delta = 1\ninternal_api_port = {internal_port}\n"
        )
        bitcoin_args = [
            "-regtest", f"-datadir={bitcoin_dir}", f"-rpcport={rpc_port}",
            "-rpcuser=test", "-rpcpassword=test",
        ]
        try:
            with (work / "bitcoin.log").open("w") as log:
                processes.append(subprocess.Popen(
                    ["bitcoind", *bitcoin_args, "-server=1", "-listen=0", "-connect=0",
                     "-dnsseed=0", "-discover=0", "-fallbackfee=0.00002"],
                    stdout=log, stderr=subprocess.STDOUT,
                ))
            cli = ["bitcoin-cli", *bitcoin_args]
            subprocess.run(
                [*cli, "-rpcwait", "-rpcwaittimeout=30", "getblockchaininfo"],
                check=True, capture_output=True, text=True, timeout=35,
            )
            subprocess.run(
                [*cli, "generatetodescriptor", "101", "raw(51)"],
                check=True, capture_output=True, text=True, timeout=30,
            )
            with (work / "tower.log").open("w") as log:
                processes.append(subprocess.Popen(
                    [str(teosd), "--datadir", str(tower_dir), "--btcnetwork", "regtest",
                     "--btcrpcconnect", "127.0.0.1", "--btcrpcport", str(rpc_port),
                     "--btcrpcuser", "test", "--btcrpcpassword", "test",
                     "--apibind", "127.0.0.1", "--apiport", str(api_port),
                     "--rpcbind", "127.0.0.1", "--rpcport", str(admin_port)],
                    stdout=log, stderr=subprocess.STDOUT,
                ))
            deadline = time.monotonic() + 45
            while True:
                if processes[-1].poll() is not None:
                    raise RuntimeError("teosd exited during startup")
                try:
                    url = f"http://127.0.0.1:{api_port}/ping"
                    with urllib.request.urlopen(url, timeout=1) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("teosd startup timed out")
                time.sleep(0.2)
            tower_id = re.search(r"tower_id: ([0-9a-f]{66})", (work / "tower.log").read_text())
            if tower_id is None:
                raise RuntimeError("teosd did not report its public identity")
            env = os.environ.copy()
            env.update(
                TEOS_E2E_URL=f"http://127.0.0.1:{api_port}",
                TEOS_E2E_TOWER_ID=tower_id[1],
                TEOS_E2E_BITCOIN_RPC_URL=f"http://127.0.0.1:{rpc_port}/",
                TEOS_E2E_BITCOIN_RPC_USER="test",
                TEOS_E2E_BITCOIN_RPC_PASSWORD="test",
            )
            # These scenarios mine on the same isolated chain. Run them one at
            # a time, each with its own wallet, identity, and client database.
            for test in ["live_teos_legacy_breach", "live_teos_anchor_breach"]:
                subprocess.run(
                    [*test_command, test, "--", "--ignored", "--exact"],
                    cwd=ROOT, env=env, check=True, timeout=300,
                )
            print("Legacy and anchor breaches with confirmed TEOS justice passed.", flush=True)
        except BaseException:
            for name in ["bitcoin.log", "tower.log"]:
                path = work / name
                if path.exists():
                    tail = "\n".join(path.read_text().splitlines()[-35:])
                    print(f"Last lines of {name}:\n{tail}", flush=True)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            print("Stopped disposable services; temporary data will be removed.", flush=True)


if __name__ == "__main__":
    main()
