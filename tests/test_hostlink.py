"""One process owns the host link; every other Hermes process on the host relays through it (hostlink.py).

Found live: Desktop sessions run in the dashboard backend, not ``gateway run``, so a tool call there must
reach the link the gateway holds.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

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


class HostLinkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.rig = Rig()
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

    async def test_another_process_relays(self):
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", CLIENT, str(ROOT / "plugin" / "tether"), str(self.dir),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), 30)
        self.assertEqual(proc.returncode, 0, err.decode()[-800:])
        res = json.loads(out.decode().strip().splitlines()[-1])
        self.assertEqual(res, {"role": "relay", "online": ["mac"], "output": "from-another-process"})

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


if __name__ == "__main__":
    unittest.main()
