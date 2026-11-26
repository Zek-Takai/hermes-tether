"""Security core: identity, TLS 1.3 pinned link + 256-bit gate, framing, pairing.

Run with Hermes's own Python (stdlib unittest; nothing to install):
    ~/.hermes/hermes-agent/venv/bin/python -m unittest discover -s tests -v
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")))     # Hermes itself, for the passphrase tests

from tether import frames, pairing, tlslink  # noqa: E402
from tether.identity import MemorySecretStore, PASSPHRASE_SECRET, load_or_create  # noqa: E402
from test_link_loopback import temp_dir  # noqa: E402


def make_identity(test, name: str):
    d = temp_dir(test, f"hp-{name}-")
    store = MemorySecretStore()
    return load_or_create(d, store, f"tether-{name}"), d, store


class IdentityTests(unittest.TestCase):
    def test_key_on_disk_is_encrypted_and_reloads(self):
        ident, d, store = make_identity(self, "a")
        raw = (d / "identity.key.enc").read_bytes()
        self.assertIn(b"ENCRYPTED PRIVATE KEY", raw)
        self.assertNotIn(b"BEGIN PRIVATE KEY", raw)
        self.assertEqual(oct((d / "identity.key.enc").stat().st_mode & 0o777), "0o600")
        again = load_or_create(d, store, "tether-a")
        self.assertEqual(again.fp, ident.fp)

    def test_missing_passphrase_refuses(self):
        _, d, _ = make_identity(self, "b")
        with self.assertRaises(RuntimeError):
            load_or_create(d, MemorySecretStore(), "tether-b")   # key on disk, secret gone

    def test_wrong_passphrase_fails_loudly(self):
        _, d, store = make_identity(self, "c")
        store.put(PASSPHRASE_SECRET, "AAAA" * 11)
        with self.assertRaises(Exception):
            load_or_create(d, store, "tether-c")


async def _serve_once(ctx, check):
    """Start a one-shot TLS server; returns (port, result future)."""
    result = asyncio.get_running_loop().create_future()

    async def handle(reader, writer):
        try:
            info = check(writer.get_extra_info("ssl_object"))
            await frames.write_frame(writer, {"t": "hello", "protocol": frames.PROTOCOL})
            result.set_result(info)
        except Exception as e:                     # noqa: BLE001
            result.set_result(e)
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    return server, server.sockets[0].getsockname()[1], result


class LinkTests(unittest.TestCase):
    def setUp(self):
        self.host, *_ = make_identity(self, "host")
        self.dev, *_ = make_identity(self, "dev")
        self.other, *_ = make_identity(self, "other")

    def _run(self, coro):
        return asyncio.run(asyncio.wait_for(coro, 20))

    def test_paired_link_negotiates_256_bit_and_passes_gate(self):
        async def go():
            sctx = tlslink.server_context(self.host, [self.dev.cert_pem], require_client_cert=True)
            server, port, res = await _serve_once(
                sctx, lambda o: tlslink.gate(o, allowed_peer_fps={self.dev.fp}))
            r, w = await asyncio.open_connection(
                "127.0.0.1", port, ssl=tlslink.client_context(self.dev, self.host.cert_pem))
            info = tlslink.gate(w.get_extra_info("ssl_object"), expected_peer_fp=self.host.fp)
            hello, _ = await frames.read_frame(r)
            frames.check_hello(hello)
            w.close(); server.close()
            return info, await res
        dev_info, host_info = self._run(go())
        self.assertIsInstance(host_info, dict)
        for info in (dev_info, host_info):
            self.assertEqual(info["version"], "TLSv1.3")
            self.assertIn(info["suite"], tlslink.ALLOWED_SUITES)
            self.assertEqual(info["bits"], 256)
        self.assertEqual(host_info["peer_fp"], self.dev.fp)

    def test_unpaired_device_is_refused_at_handshake(self):
        async def go():
            sctx = tlslink.server_context(self.host, [self.dev.cert_pem], require_client_cert=True)
            server, port, _ = await _serve_once(sctx, lambda o: tlslink.gate(o))
            try:
                r, w = await asyncio.open_connection(
                    "127.0.0.1", port, ssl=tlslink.client_context(self.other, self.host.cert_pem))
                await frames.read_frame(r)        # server drops an unverified client
                return "connected"
            except (ssl_errors()) as e:
                return type(e).__name__
            finally:
                server.close()
        self.assertNotEqual(self._run(go()), "connected")

    def test_device_refuses_fake_host_during_pairing(self):
        """Pairing mode: no pinned host cert yet, so the gate checks host_fp from the link."""
        async def go():
            fake = tlslink.server_context(self.other, [], require_client_cert=False)   # attacker's host
            server, port, _ = await _serve_once(fake, lambda o: tlslink.gate(o))
            r, w = await asyncio.open_connection("127.0.0.1", port, ssl=tlslink.client_context(self.dev, None))
            try:
                tlslink.gate(w.get_extra_info("ssl_object"), expected_peer_fp=self.host.fp)
                return "accepted"
            except tlslink.LinkSecurityError as e:
                return str(e)
            finally:
                w.close(); server.close()
        self.assertIn("does not match", self._run(go()))

    def test_gate_rejects_weak_suite_and_old_tls(self):
        class Fake:
            def __init__(self, version, suite, bits):
                self._v, self._c = version, (suite, version, bits)
            def version(self): return self._v
            def cipher(self): return self._c
            def getpeercert(self, binary_form=False): return b""
        with self.assertRaisesRegex(tlslink.LinkSecurityError, "256-bit"):
            tlslink.gate(Fake("TLSv1.3", "TLS_AES_128_GCM_SHA256", 128))
        with self.assertRaisesRegex(tlslink.LinkSecurityError, "TLS 1.3"):
            tlslink.gate(Fake("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", 256))


def ssl_errors():
    import ssl
    return (ssl.SSLError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError)


class FrameTests(unittest.TestCase):
    def test_roundtrip_and_chunking(self):
        payload = os.urandom(frames.MAX_BODY * 3 + 17)
        r = frames.Reassembler()
        out = None
        for h, b in frames.split_body("c1", payload):
            out = r.add(h, b) or out
        self.assertEqual(out, payload)

    def test_out_of_order_chunk_is_rejected(self):
        r = frames.Reassembler()
        with self.assertRaises(frames.FrameError):
            r.add({"t": "chunk", "id": "x", "seq": 1, "last": False}, b"a")

    def test_version_mismatch_is_a_clear_refusal(self):
        with self.assertRaisesRegex(frames.FrameError, "update tether on both machines"):
            frames.check_hello({"t": "hello", "protocol": {"major": 99, "minor": 0}})


class PairingTests(unittest.TestCase):
    HOST_FP, DEV_FP, MITM_FP = "a" * 64, "b" * 64, "c" * 64

    def setUp(self):
        self.t = [0.0]
        self.book = pairing.OfferBook(clock=lambda: self.t[0])
        self.link = self.book.create("mac", "192.0.2.10", 9130, self.HOST_FP)

    def test_link_roundtrip(self):
        parsed = pairing.PairingLink.parse(self.link.to_text())
        self.assertEqual(parsed, self.link)
        with self.assertRaises(pairing.PairingError):
            pairing.PairingLink.parse(self.link.to_text().replace("tether", "https"))

    def test_honest_pairing_both_proofs_verify(self):
        nonce = self.book.new_nonce("mac")
        proof = pairing.device_proof(self.link.secret, self.HOST_FP, self.DEV_FP, "mac", nonce)
        hp = self.book.check("mac", self.HOST_FP, self.DEV_FP, nonce, proof)
        self.assertTrue(pairing.verify(
            pairing.host_proof(self.link.secret, self.HOST_FP, self.DEV_FP, "mac", nonce), hp))

    def test_mitm_sees_different_fingerprints_and_fails(self):
        nonce = self.book.new_nonce("mac")
        # The device talks to the MITM, so it proves over the MITM's fingerprint...
        proof = pairing.device_proof(self.link.secret, self.MITM_FP, self.DEV_FP, "mac", nonce)
        # ...but the host checks over its own fingerprint and the MITM's device-side cert.
        with self.assertRaises(pairing.PairingError):
            self.book.check("mac", self.HOST_FP, self.MITM_FP, nonce, proof)

    def test_nonce_cannot_be_replayed(self):
        nonce = self.book.new_nonce("mac")
        proof = pairing.device_proof(self.link.secret, self.HOST_FP, self.DEV_FP, "mac", nonce)
        self.book.check("mac", self.HOST_FP, self.DEV_FP, nonce, proof)
        with self.assertRaisesRegex(pairing.PairingError, "nonce"):
            self.book.check("mac", self.HOST_FP, self.DEV_FP, nonce, proof)

    def test_expired_and_burned_links_are_dead(self):
        self.book.burn("mac")
        with self.assertRaises(pairing.PairingError):
            self.book.new_nonce("mac")
        self.book.create("mac", "h", 1, self.HOST_FP, ttl_s=600)
        self.t[0] = 601
        with self.assertRaisesRegex(pairing.PairingError, "expired"):
            self.book.new_nonce("mac")

    def test_repeated_wrong_proofs_revoke_the_offer(self):
        for _ in range(pairing.MAX_FAILURES):
            nonce = self.book.new_nonce("mac")
            with self.assertRaises(pairing.PairingError):
                self.book.check("mac", self.HOST_FP, self.DEV_FP, nonce, b"\x00" * 32)
        with self.assertRaisesRegex(pairing.PairingError, "no open pairing offer"):
            self.book.new_nonce("mac")


DUMMY_PASSPHRASE = "dummy-passphrase-value-123"


def _clear_masks() -> None:
    try:
        from agent.redact import clear_vault_redaction_values
    except Exception:  # noqa: BLE001 - Hermes not importable here
        return
    clear_vault_redaction_values()


class PassphraseProtectionTests(unittest.TestCase):
    """The key passphrase leaves the environment; identity loads once per process (design D13)."""

    def setUp(self):
        from tether import identity as ident
        self.ident = ident
        ident._HELD.clear()
        self.env = unittest.mock.patch.dict(os.environ, {PASSPHRASE_SECRET: DUMMY_PASSPHRASE,
                                                         "HOMEPORT_KEY_PASSPHRASE": DUMMY_PASSPHRASE})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.ident._HELD.clear()
        _clear_masks()

    def test_both_names_leave_the_process_environment(self):
        store = MemorySecretStore()
        store.put(PASSPHRASE_SECRET, DUMMY_PASSPHRASE)
        self.ident.protect_passphrase(store)
        self.assertFalse(PASSPHRASE_SECRET in os.environ, "still in the environment")
        self.assertFalse("HOMEPORT_KEY_PASSPHRASE" in os.environ, "still in the environment")

    def test_each_hermes_home_keeps_its_own_passphrase(self):
        """One process can serve several profiles: a passphrase held for one home is never answered for another."""
        from tether.identity import HermesSecretStore
        a, b = str(temp_dir(self, "hp-home-a-")), str(temp_dir(self, "hp-home-b-"))
        with unittest.mock.patch.object(self.ident, "_home_key", return_value=a):
            store = MemorySecretStore()
            store.put(PASSPHRASE_SECRET, "dummy-for-home-a")
            self.ident.protect_passphrase(store)
            self.assertEqual(HermesSecretStore().get(PASSPHRASE_SECRET), "dummy-for-home-a")
        self.assertEqual(self.ident._HELD, {(a, PASSPHRASE_SECRET): "dummy-for-home-a"})
        # Home b, with a's value held and nothing for b anywhere in Hermes: b is not answered with a's value (F94).
        import agent.secret_scope  # noqa: F401 - imported so the two readers can be stood in for
        import hermes_cli.config  # noqa: F401
        with unittest.mock.patch.object(self.ident, "_home_key", return_value=b), \
                unittest.mock.patch("agent.secret_scope.get_secret", return_value=None), \
                unittest.mock.patch("hermes_cli.config.get_env_value", return_value=None):
            answer = HermesSecretStore().get(PASSPHRASE_SECRET)
        self.assertTrue(answer is None, "home b was answered with another home's value")
        with unittest.mock.patch.object(self.ident, "_home_key", return_value=b):
            other = MemorySecretStore()
            other.put(PASSPHRASE_SECRET, "dummy-for-home-b")
            self.ident.protect_passphrase(other)
        self.assertEqual(self.ident._HELD[(a, PASSPHRASE_SECRET)], "dummy-for-home-a")
        self.assertEqual(self.ident._HELD[(b, PASSPHRASE_SECRET)], "dummy-for-home-b")

    def test_shield_empties_a_reloaded_environment_and_keeps_nothing_from_it(self):
        store = MemorySecretStore()
        store.put(PASSPHRASE_SECRET, DUMMY_PASSPHRASE)
        self.ident.protect_passphrase(store)
        held = dict(self.ident._HELD)
        os.environ[PASSPHRASE_SECRET] = "dummy-from-a-reload"
        os.environ["HOMEPORT_KEY_PASSPHRASE"] = "dummy-from-a-reload"
        self.ident.shield_children()
        self.assertFalse(PASSPHRASE_SECRET in os.environ, "still in the environment")
        self.assertFalse("HOMEPORT_KEY_PASSPHRASE" in os.environ, "still in the environment")
        self.assertEqual(self.ident._HELD, held)                  # a value found in the environment is not kept

    def test_identity_loads_once_and_works_with_the_variable_absent(self):
        from tether import config
        home = temp_dir(self, "hp-once-")
        store = MemorySecretStore()
        settings = config.Settings(roles={"device"}, name="dummy", listen_host="127.0.0.1", listen_port=9130,
                                   grant_idle_minutes=15, consent_timeout_seconds=15)
        with unittest.mock.patch.object(config, "data_dir", return_value=home / "tether"), \
                unittest.mock.patch.object(config, "HermesSecretStore", return_value=store):
            config.reset_identity_cache()
            first = config.identity(settings)
            self.assertFalse(PASSPHRASE_SECRET in os.environ, "still in the environment")
            self.assertIs(config.identity(settings), first)
            # a fresh load (as in a new process) reads the passphrase from the store, not the environment
            config.reset_identity_cache()
            self.assertFalse(PASSPHRASE_SECRET in os.environ, "still in the environment")
            again = config.identity(settings)
            self.assertEqual(again.fp, first.fp)
            config.reset_identity_cache()


if __name__ == "__main__":
    unittest.main()


class PassphraseHomeTests(unittest.TestCase):
    """Where the passphrase is read and masked when Hermes names the home in more than one way."""

    def setUp(self):
        try:
            import hermes_constants  # noqa: F401
            from agent.redact import redact_sensitive_text  # noqa: F401
        except Exception:  # noqa: BLE001
            self.skipTest("Hermes source not importable")
        from tether import identity as ident
        self.ident = ident
        ident._HELD.clear()
        self.env = unittest.mock.patch.dict(os.environ)
        self.env.start()
        for name in (PASSPHRASE_SECRET, "HOMEPORT_KEY_PASSPHRASE"):
            os.environ.pop(name, None)
        self.addCleanup(self.env.stop)
        self.addCleanup(ident._HELD.clear)
        self.addCleanup(_clear_masks)

    def _symlinked_home(self) -> tuple[Path, Path]:
        real = temp_dir(self, "hp-real-home-").resolve()
        link = temp_dir(self, "hp-link-") / "home"
        os.symlink(real, link)
        return real, link

    def test_a_symlinked_home_is_masked_without_any_shield_call(self):
        """Hermes's plugin loader names the home resolved while plugins register; at run time it is named as written.
        The value held and masked at start-up must work under both names (F48)."""
        from agent.redact import redact_sensitive_text
        from hermes_constants import hermes_home_key, reset_hermes_home_override, set_hermes_home_override
        from tether.identity import HermesSecretStore
        real, link = self._symlinked_home()
        os.environ["HERMES_HOME"] = str(link)
        _clear_masks()
        token = set_hermes_home_override(hermes_home_key(link))     # what the plugin loader binds for register()
        try:
            store = MemorySecretStore()
            store.put(PASSPHRASE_SECRET, DUMMY_PASSPHRASE)
            self.ident.protect_passphrase(store)
        finally:
            reset_hermes_home_override(token)
        out = redact_sensitive_text(f"x {DUMMY_PASSPHRASE} y", force=True)       # run time: the home as written
        self.assertFalse(DUMMY_PASSPHRASE in out, "the passphrase was not masked at run time")
        import hermes_cli.config  # noqa: F401 - imported so its reader can be stood in for
        with unittest.mock.patch("agent.secret_scope.get_secret", return_value=None), \
                unittest.mock.patch("hermes_cli.config.get_env_value", return_value=None):
            answer = HermesSecretStore().get(PASSPHRASE_SECRET)
        self.assertTrue(answer == DUMMY_PASSPHRASE, "the value held at start-up is not found at run time")

    def test_multiplexed_with_no_scope_reads_this_homes_own_env(self):
        """Hermes's external cron worker turns multiplexing on before plugins load: no profile scope is bound and
        Hermes's readers refuse. The store reads this home's own .env instead of failing (F49 hardening)."""
        from agent.secret_scope import reset_multiplex_context, set_multiplex_context
        from tether.identity import HermesSecretStore
        home = temp_dir(self, "hp-mx-home-")
        (home / ".env").write_text(f"{PASSPHRASE_SECRET}={DUMMY_PASSPHRASE}\n")
        os.environ["HERMES_HOME"] = str(home)
        token = set_multiplex_context(True)
        try:
            value = HermesSecretStore().get(PASSPHRASE_SECRET)
        finally:
            reset_multiplex_context(token)
        self.assertTrue(value == DUMMY_PASSPHRASE, "this home's own passphrase was not read")


# Run in a child Python started with the passphrase in its exec environment, as Hermes starts a gateway itself
# (gateway ensure: every .env secret in the start-up environment). Prints booleans only.
_STARTUP_CHILD = r"""
import os, subprocess, sys
sys.path.insert(0, sys.argv[1]); sys.path.insert(1, sys.argv[2])
NAME, VALUE = "TETHER_KEY_PASSPHRASE", os.environ["TETHER_KEY_PASSPHRASE"]
os.environ[NAME] = VALUE      # Hermes's .env load: environ[] no longer points at the start-up copy
from tether import identity
from tether.device_exec import LocalExec
from tether.provider import TetherEnvironment
store = identity.MemorySecretStore(); store.put(NAME, VALUE)
identity.protect_passphrase(store)
READ = ('if [ -r /proc/$PPID/environ ]; then tr "\\0" "\\n" < /proc/$PPID/environ; '
        'else ps -E -ww -o command= -p $PPID; fi')
direct = subprocess.run(["/bin/sh", "-c", READ], capture_output=True, text=True).stdout
local = LocalExec()
try:
    device = local._run({"command": READ}, b"")[1].decode(errors="replace")
finally:
    local.close_all()
env = TetherEnvironment("~", 30, "t-startup")
try:
    host = str(env._run_local(READ, "", 30, None).get("output") or "")
finally:
    env.cleanup()
print("seen-other", "PATH=" in direct)
print("leak-direct", VALUE in direct)
print("leak-device", VALUE in device)
print("leak-host", VALUE in host)
"""


class StartupSpotTests(unittest.TestCase):
    def test_only_the_passphrase_values_are_found_in_a_start_up_area(self):
        """The reader of the start-up area (both systems) finds each passphrase value, at its exact place, and
        nothing else; a value already overwritten is not found again (F2)."""
        from tether.identity import _value_spots
        area = (b"PATH=/bin\0TETHER_KEY_PASSPHRASE=abc\0XTETHER_KEY_PASSPHRASE=no\0"
                b"HOMEPORT_KEY_PASSPHRASE=de\0TETHER_KEY_PASSPHRASE=***\0\0\0")
        spots = _value_spots(area, 0)
        self.assertEqual([area[at + k:at + k + n] for at, k, n in spots], [b"abc", b"de"])
        self.assertEqual([area[at:at + k] for at, k, _ in spots],
                         [b"TETHER_KEY_PASSPHRASE=", b"HOMEPORT_KEY_PASSPHRASE="])
        self.assertEqual(_value_spots(b"TETHER_KEY_PASSPHRASE=abc", 0), [(0, 22, 3)])     # last string, no NUL


@unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"),
                     "macOS and Linux keep a start-up copy")
class StartupEnvironmentTests(unittest.TestCase):
    def test_the_start_up_copy_of_the_environment_does_not_show_the_passphrase(self):
        """A program of the same user lists a process's start-up environment (ps -E, /proc/<pid>/environ). After the
        plugin has protected the passphrase, a command run from that process, plain or through the plugin's device
        and host terminals, does not find it there (F2)."""
        try:
            import tools.environments.local  # noqa: F401
        except Exception:  # noqa: BLE001
            self.skipTest("Hermes source not importable")
        import subprocess
        root = Path(__file__).resolve().parents[1]
        script = temp_dir(self, "hp-startup-") / "child.py"
        script.write_text(_STARTUP_CHILD)
        env = {k: v for k, v in os.environ.items() if k not in (PASSPHRASE_SECRET, "HOMEPORT_KEY_PASSPHRASE")}
        env.update({PASSPHRASE_SECRET: DUMMY_PASSPHRASE, "HERMES_HOME": str(temp_dir(self, "hp-startup-home-")),
                    "PYTHONDONTWRITEBYTECODE": "1"})
        out = subprocess.run([sys.executable, str(script), str(root / "plugin" / "tether"),
                              str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent"))],
                             env=env, capture_output=True, text=True, timeout=180)
        lines = dict(line.split(" ", 1) for line in out.stdout.splitlines() if line.startswith(("leak-", "seen-")))
        self.assertEqual(lines.get("seen-other"), "True", "the child could not list the start-up environment")
        for where in ("leak-direct", "leak-device", "leak-host"):
            self.assertEqual(lines.get(where), "False", f"{where}: the start-up environment shows the passphrase")


class MigrationTests(unittest.TestCase):
    """The working name was homeport: keys, pins and the key's passphrase secret carry over on first load."""

    def test_legacy_passphrase_and_data_folder_carry_over(self):
        from tether import store
        from tether.identity import LEGACY_PASSPHRASE_SECRETS
        old_ident, d, old_store = make_identity(self, "legacy")
        legacy_secret = old_store.get(PASSPHRASE_SECRET)
        fresh = MemorySecretStore()
        fresh.put(LEGACY_PASSPHRASE_SECRETS[0], legacy_secret)          # as an old install has it
        again = load_or_create(d, fresh, "tether-legacy")
        self.assertEqual(again.fp, old_ident.fp)
        self.assertEqual(fresh.get(PASSPHRASE_SECRET), legacy_secret)   # stored under the new name too
        home = temp_dir(self, "hp-home-")
        (home / "homeport").mkdir()
        (home / "homeport" / "paired_host.json").write_text("{}")
        old = os.environ.get("HERMES_HOME")
        os.environ["HERMES_HOME"] = str(home)
        try:
            with unittest.mock.patch.dict(sys.modules, {"hermes_constants": None}):
                new_dir = store.data_dir()
        finally:
            if old is None:
                os.environ.pop("HERMES_HOME", None)
            else:
                os.environ["HERMES_HOME"] = old
        self.assertEqual(new_dir, home / "tether")
        self.assertTrue((home / "tether" / "paired_host.json").exists())
        self.assertFalse((home / "homeport").exists())
