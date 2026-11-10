"""Loopback end-to-end: pair over the wire, connect with pinned TLS, consent gate, call, unpair.

    ~/.hermes/hermes-agent/venv/bin/python -m unittest discover -s tests -v
"""
from __future__ import annotations

import asyncio
import socket
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))

from tether import pairing  # noqa: E402
from tether.consent import ConsentGate  # noqa: E402
from tether.device import DeviceService  # noqa: E402
from tether.host import HostService  # noqa: E402
from tether.identity import MemorySecretStore, load_or_create  # noqa: E402
from tether.link import RemoteError  # noqa: E402
from tether.store import DevicePins, HostPin  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakePrompt:
    def __init__(self, answer: bool) -> None:
        self.answer, self.asked = answer, []

    async def __call__(self, text: str, timeout_s: float) -> bool:
        self.asked.append(text)
        return self.answer


async def echo_exec(args, body):
    proc = await asyncio.create_subprocess_shell(args["command"], stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.STDOUT)
    out, _ = await proc.communicate()
    return {"output": out.decode(), "returncode": proc.returncode}, b""


async def big_body(args, body):
    return {"n": len(body)}, body[::-1]


class Rig:
    def __init__(self, consent_answer: bool = True, handlers=None, capabilities=None) -> None:
        hd, dd = Path(tempfile.mkdtemp(prefix="hp-h-")), Path(tempfile.mkdtemp(prefix="hp-d-"))
        self.host_ident = load_or_create(hd, MemorySecretStore(), "tether-host")
        self.dev_ident = load_or_create(dd, MemorySecretStore(), "tether-dev")
        self.pins, self.host_pin = DevicePins(hd), HostPin(dd)
        self.prompt = FakePrompt(consent_answer)
        self.consent = ConsentGate(idle_minutes=15, timeout_s=5, prompt=self.prompt)
        self.host = HostService(self.host_ident, self.pins, "127.0.0.1", free_port(), label="Test host")
        self.device = DeviceService(self.dev_ident, self.host_pin, self.consent, "mac",
                                    handlers or {"exec": echo_exec, "echo_body": big_body},
                                    lambda: capabilities or {"screen": True})

    async def pair(self, confirm_answer: bool = True, tamper=None):
        links: asyncio.Queue = asyncio.Queue()

        async def confirm(name, details):
            self.confirmed = (name, details)
            return confirm_answer

        task = asyncio.create_task(self.host.pair("mac", "127.0.0.1", free_port(), confirm, links.put_nowait))
        text = await links.get()
        if tamper:
            text = tamper(text)
        try:
            return await self.device.join(text), task
        except Exception:
            task.cancel()
            raise

    async def connect(self):
        await self.host._reload()
        self.device.start()
        for _ in range(100):
            if "mac" in self.host.devices and self.host.devices["mac"].announce:
                return
            await asyncio.sleep(0.05)
        raise AssertionError("device never connected")


class LoopbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_pair_connect_consent_call_unpair(self):
        rig = Rig()
        joined, task = await rig.pair()
        self.assertEqual(joined["host_label"], "Test host")
        self.assertEqual((await task)["fp"], rig.dev_ident.fp)
        self.assertEqual(rig.pins.all()["mac"]["fp"], rig.dev_ident.fp)
        self.assertEqual(rig.host_pin.get()["fp"], rig.host_ident.fp)

        await rig.connect()
        row = rig.host.status()[0]
        self.assertTrue(row["online"])
        self.assertEqual(row["link"]["bits"], 256)
        self.assertTrue(row["capabilities"]["screen"])

        data, _ = await rig.host.call("mac", "exec", {"command": "echo hi", "session": "s1"})
        self.assertEqual((data["output"].strip(), data["returncode"]), ("hi", 0))
        await rig.host.call("mac", "exec", {"command": "true", "session": "s1"})
        self.assertEqual(len(rig.prompt.asked), 1)            # one Allow covers the session
        await rig.host.call("mac", "exec", {"command": "true", "session": "s2"})
        self.assertEqual(len(rig.prompt.asked), 2)            # a new session asks again

        payload = bytes(range(256)) * 4096                    # 1 MiB: chunked both ways
        data, back = await rig.host.call("mac", "echo_body", {"session": "s1"}, payload)
        self.assertEqual((data["n"], back), (len(payload), payload[::-1]))

        rig.pins.remove("mac")
        await rig.host._reload()
        self.assertNotIn("mac", rig.host.devices)
        with self.assertRaises(ConnectionError):
            await rig.host.call("mac", "exec", {"command": "true"})
        rig.device._task.cancel()

    async def test_denied_consent_blocks_the_call(self):
        rig = Rig(consent_answer=False)
        _, task = await rig.pair()
        await task
        await rig.connect()
        with self.assertRaises(RemoteError) as cm:
            await rig.host.call("mac", "exec", {"command": "echo no", "session": "s1"})
        self.assertIn("did not allow", str(cm.exception))
        rig.device._task.cancel()

    async def test_owner_declines_pairing(self):
        rig = Rig()
        with self.assertRaises(pairing.PairingError):
            await rig.pair(confirm_answer=False)
        self.assertEqual(rig.pins.all(), {})
        self.assertIsNone(rig.host_pin.get())

    async def test_wrong_secret_or_fake_host_is_refused(self):
        rig = Rig()

        def bad_secret(text):
            head, _, tail = text.partition("#")
            fp, _, secret = tail.partition(".")
            return f"{head}#{fp}.{'A' * len(secret)}"

        with self.assertRaises(Exception):
            await rig.pair(tamper=bad_secret)
        self.assertEqual(rig.pins.all(), {})

        def other_host(text):
            head, _, tail = text.partition("#")
            _, _, secret = tail.partition(".")
            return f"{head}#{'0' * 64}.{secret}"

        rig2 = Rig()
        with self.assertRaises(Exception):
            await rig2.pair(tamper=other_host)
        self.assertEqual(rig2.pins.all(), {})


if __name__ == "__main__":
    unittest.main()


class UnderTruststoreTests(unittest.IsolatedAsyncioTestCase):
    """Hermes injects truststore at startup (agent/ssl_verify.py): every ssl.SSLContext then verifies peers with
    the OS store, which rejects our pinned Ed25519 certificates. The link must not be affected."""

    def setUp(self):
        try:
            import truststore
        except ImportError:
            self.skipTest("truststore not installed")
        truststore.inject_into_ssl()
        self.addCleanup(truststore.extract_from_ssl)

    async def test_pair_connect_call(self):
        rig = Rig()
        _, task = await rig.pair()
        await task
        await rig.connect()
        data, _ = await rig.host.call("mac", "exec", {"command": "echo ok", "session": "s1"})
        self.assertEqual(data["output"].strip(), "ok")
        rig.device._task.cancel()
