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

from tether import frames, pairing, tlslink  # noqa: E402
from tether.identity import MemorySecretStore, PASSPHRASE_SECRET, load_or_create  # noqa: E402


def make_identity(name: str):
    d = Path(tempfile.mkdtemp(prefix=f"hp-{name}-"))
    store = MemorySecretStore()
    return load_or_create(d, store, f"tether-{name}"), d, store


class IdentityTests(unittest.TestCase):
    def test_key_on_disk_is_encrypted_and_reloads(self):
        ident, d, store = make_identity("a")
        raw = (d / "identity.key.enc").read_bytes()
        self.assertIn(b"ENCRYPTED PRIVATE KEY", raw)
        self.assertNotIn(b"BEGIN PRIVATE KEY", raw)
        self.assertEqual(oct((d / "identity.key.enc").stat().st_mode & 0o777), "0o600")
        again = load_or_create(d, store, "tether-a")
        self.assertEqual(again.fp, ident.fp)

    def test_missing_passphrase_refuses(self):
        _, d, _ = make_identity("b")
        with self.assertRaises(RuntimeError):
            load_or_create(d, MemorySecretStore(), "tether-b")   # key on disk, secret gone

    def test_wrong_passphrase_fails_loudly(self):
        _, d, store = make_identity("c")
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
        self.host, *_ = make_identity("host")
        self.dev, *_ = make_identity("dev")
        self.other, *_ = make_identity("other")

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


if __name__ == "__main__":
    unittest.main()


class MigrationTests(unittest.TestCase):
    """The working name was homeport: keys, pins and the key's passphrase secret carry over on first load."""

    def test_legacy_passphrase_and_data_folder_carry_over(self):
        from tether import store
        from tether.identity import LEGACY_PASSPHRASE_SECRETS
        old_ident, d, old_store = make_identity("legacy")
        legacy_secret = old_store.get(PASSPHRASE_SECRET)
        fresh = MemorySecretStore()
        fresh.put(LEGACY_PASSPHRASE_SECRETS[0], legacy_secret)          # as an old install has it
        again = load_or_create(d, fresh, "tether-legacy")
        self.assertEqual(again.fp, old_ident.fp)
        self.assertEqual(fresh.get(PASSPHRASE_SECRET), legacy_secret)   # stored under the new name too
        home = Path(tempfile.mkdtemp(prefix="hp-home-"))
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
