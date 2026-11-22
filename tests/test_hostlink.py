"""One process owns the host link; every other Hermes process on the host relays through it (hostlink.py).

Found live: Desktop sessions run in the dashboard backend, not ``gateway run``, so a tool call there must
reach the link the gateway holds.
"""
from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugin" / "tether"))

from tether.host import HostService  # noqa: E402
from tether.hostlink import HostLink  # noqa: E402

from test_link_loopback import Rig  # noqa: E402

CLIENT = textwrap.dedent("""
    import asyncio, json, sys
    sys.path.insert(0, sys.argv[1])
    from tether.hostlink import HostLink
    def no_owner():
        raise AssertionError("the relay client must not become owner while the owner runs")
    async def main():
        link = HostLink(__import__("pathlib").Path(sys.argv[2]), no_owner)
        rows = await link.list_devices()
        data, out = await link.call("mac", "exec", {"command": "echo from-another-process", "session": "s1"})
        print(json.dumps({"role": link.role, "online": [r["name"] for r in rows if r["online"]],
                          "output": data["output"].strip()}))
        await link.close()
    asyncio.run(main())
""")


OUTSIDER = textwrap.dedent("""
    import asyncio, json, sys
    sys.path.insert(0, sys.argv[1])
    from tether.hostlink import HostLink
    def no_owner():
        raise AssertionError("the relay client must not become owner while the owner runs")
    async def main():
        link = HostLink(__import__("pathlib").Path(sys.argv[2]), no_owner)
        try:
            data, _ = await link.call("mac", "exec", json.loads(sys.argv[3]))
            print(json.dumps({"ran": data["output"].strip()}))
        except Exception as e:
            print(json.dumps({"refused": str(e)}))
        await link.close()
    asyncio.run(main())
""")


class HostLinkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.rig = Rig()
        self.addCleanup(self.rig.close)
        _, task = await self.rig.pair()
        await task
        self.dir = self.rig.pins.path.parent
        self.owner = HostLink(self.dir, lambda: self.rig.host)
        await self.owner.ensure()
        self.assertEqual(self.owner.role, "owner")
        self.rig.device.start()
        await self._wait_online(self.rig.host)

    async def asyncTearDown(self):
        self.rig.device._task.cancel()
        await self.owner.close()

    async def _wait_online(self, service):
        for _ in range(200):
            if "mac" in service.devices and service.devices["mac"].announce:
                return
            await asyncio.sleep(0.05)
        raise AssertionError("device never connected")

    async def test_second_link_in_process_relays(self):
        other = HostLink(self.dir, lambda: self.fail("must relay, not own"))
        try:
            rows = await other.list_devices()
            self.assertEqual(other.role, "relay")
            self.assertTrue(rows[0]["online"])
            self.assertEqual(rows[0]["link"]["bits"], 256)
            data, _ = await other.call("mac", "exec", {"command": "echo relayed", "session": "s1"})
            self.assertEqual(data["output"].strip(), "relayed")
            with self.assertRaises(Exception) as cm:
                await other.call("ghost", "exec", {"command": "true"})
            self.assertIn("no paired device", str(cm.exception))
        finally:
            await other.close()

    async def test_a_relayed_call_keeps_its_key_binding(self):
        """D43: a process that relays through the owner names the key its call is for; the owner sends it only over
        that key's link."""
        other = HostLink(self.dir, lambda: self.fail("must relay, not own"))
        try:
            with self.assertRaises(Exception) as cm:
                await other.call("mac", "exec", {"command": "echo no", "session": "s9"}, expect_fp="0" * 64)
            self.assertIn("different paired key", str(cm.exception))
            self.assertEqual(self.rig.prompt.asked, [])
            data, _ = await other.call("mac", "exec", {"command": "echo yes", "session": "s9"},
                                       expect_fp=self.rig.dev_ident.fp)
            self.assertEqual(data["output"].strip(), "yes")
        finally:
            await other.close()

    async def test_another_process_relays(self):
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", CLIENT, str(ROOT / "plugin" / "tether"), str(self.dir),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), 30)
        self.assertEqual(proc.returncode, 0, err.decode()[-800:])
        res = json.loads(out.decode().strip().splitlines()[-1])
        self.assertEqual(res, {"role": "relay", "online": ["mac"], "output": "from-another-process"})

    async def _outsider(self, args):
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", OUTSIDER, str(ROOT / "plugin" / "tether"), str(self.dir), json.dumps(args),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), 30)
        self.assertEqual(proc.returncode, 0, err.decode()[-800:])
        return json.loads(out.decode().strip().splitlines()[-1])

    async def test_another_program_cannot_ride_an_open_session(self):
        """D33. The relay socket takes calls from any program of this user. Naming a session that is open
        gives such a program nothing: it holds no grant token, so the person at the device is asked again."""
        data, _ = await self.owner.call("mac", "exec", {"command": "echo opened", "session": "A"})
        grant = data["grant"]
        self.assertEqual(len(self.rig.prompt.asked), 1)
        self.rig.prompt.answer = False                        # nobody at the device expects another request
        for extra in ({}, {"host_gate": True}, {"grant": "guess"}):
            res = await self._outsider({"command": "echo rode-along", "session": "A", **extra})
            self.assertIn("did not allow remote use", res.get("refused", ""), res)
        self.assertEqual(len(self.rig.prompt.asked), 2)       # asked once more, then the cool-down answers
        data, _ = await self.owner.call("mac", "exec", {"command": "echo mine", "session": "A", "grant": grant})
        self.assertEqual(data["output"].strip(), "mine")      # the real session carries on
        res = await self._outsider({"command": "true", "session": ".."})
        self.assertIn("unusable session id", res.get("refused", ""), res)

    async def test_takeover_when_the_owner_exits(self):
        rig = self.rig

        def new_service():
            return HostService(rig.host_ident, rig.pins, "127.0.0.1", rig.host.listen_port, label="Test host")

        other = HostLink(self.dir, new_service)
        await other.list_devices()
        self.assertEqual(other.role, "relay")
        await self.owner.close()                       # the owner process goes away
        for _ in range(100):
            try:
                await other.list_devices()
                break
            except Exception:  # noqa: BLE001 - the relay sees the owner drop first
                await asyncio.sleep(0.05)
        self.assertEqual(other.role, "owner")
        await self._wait_online(other.service)         # the device reconnects to the new owner on its own
        data, _ = await other.call("mac", "exec", {"command": "echo new-owner", "session": "s1"})
        self.assertEqual(data["output"].strip(), "new-owner")
        await other.close()


class OwnerStartTests(unittest.IsolatedAsyncioTestCase):
    """F37: a first start that fails (the port held or the address not up yet at boot, a pin the listener cannot be
    built from, the service not built) must not keep link.lock with no service, which refused every Hermes process
    on the host until a restart."""

    async def asyncSetUp(self):
        self.rig = Rig()
        self.addCleanup(self.rig.close)
        _, task = await self.rig.pair()
        await task
        self.dir = self.rig.pins.path.parent
        patch = mock.patch.object(HostService, "WATCH_INTERVAL_S", 0.05)
        patch.start()
        self.addCleanup(patch.stop)

    def _service(self):
        return HostService(self.rig.host_ident, self.rig.pins, "127.0.0.1", self.rig.host.listen_port,
                           label="Test host")

    async def test_a_port_held_at_start_is_retried_and_the_link_stays_owned(self):
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", self.rig.host.listen_port))
        blocker.listen(1)
        link = HostLink(self.dir, self._service)
        self.addAsyncCleanup(link.close)
        try:
            await link.ensure()                               # no error: the service is up, not yet listening
            self.assertEqual(link.role, "owner")
            self.assertIsNone(link.service._server)
            other = HostLink(self.dir, lambda: self.fail("must relay, not own"))
            self.addAsyncCleanup(other.close)
            rows = await other.list_devices()                 # another process relays instead of waiting forever
            self.assertEqual((other.role, rows[0]["online"]), ("relay", False))
        finally:
            blocker.close()                                   # the port is free again
        self.rig.device.start()
        self.addCleanup(self.rig.device._task.cancel)
        for _ in range(200):
            if "mac" in link.service.devices and link.service.devices["mac"].announce:
                break
            await asyncio.sleep(0.05)
        self.assertIsNotNone(link.service._server, "the listener never came up once the port was free")
        self.assertIn("mac", link.service.devices, "the device never connected once the port was free")

    async def test_a_service_that_fails_to_start_gives_the_lock_back(self):
        built = []

        def flaky():
            built.append(1)
            if len(built) == 1:
                raise RuntimeError("the key could not be loaded (once)")
            return self._service()

        link = HostLink(self.dir, flaky)
        self.addAsyncCleanup(link.close)
        with self.assertRaises(RuntimeError):
            await link.ensure()
        self.assertIsNone(link._lock_fh, "link.lock was kept after the service failed to start")
        await link.ensure()                                   # the next call takes the link
        self.assertEqual(link.role, "owner")
        self.assertEqual(len(built), 2)


if __name__ == "__main__":
    unittest.main()
