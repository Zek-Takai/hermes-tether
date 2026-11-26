"""The authenticator setup shows the new key as a code to scan, with the key as text under it (design D84).

Nothing is shown on screen here and nothing runs a box: the tests read the script text, the bytes that go to the
box program on stdin and what the setup flow asks for. A test never prints a key, a code or a URI.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")))

from test_enroll import Clock, Person, seal, seed_in  # noqa: E402
from test_link_loopback import temp_dir  # noqa: E402
from tether import enroll, seedstore as ss  # noqa: E402

KEY = "GEZDGNBVGY3TQOJQ GEZDGNBVGY3TQOJQ"        # a made-up key: never a real one
URI = ("otpauth://totp/Hermes%20Tether?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
       "&issuer=Hermes%20Tether&algorithm=SHA1&digits=6&period=30")
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def run(coro):
    import asyncio
    return asyncio.run(coro)


def the_qr() -> enroll.QrCode:
    """The code box the setup shows, with a made-up key."""
    return enroll.QrCode(uri=enroll.otpauth_uri(KEY, "mac"), key_text=KEY,
                         fallback=f"Can't scan? Type this key: {KEY}",
                         text="1. In the app, add a new entry and choose to scan a QR code.\n"
                              "2. Scan the code below with the app.\n"
                              "3. Type: time-based, 6 digits, every 30 seconds (the app's usual default).",
                         plain_text="Add this key to your authenticator app on your phone:\n\n"
                                    "1. In the app, add a new entry and choose to enter a setup key "
                                    "(not to scan a QR code).\n2. Name: Hermes Tether\n"
                                    f"3. Key: {KEY}\n")


class FakeBox:
    """A stand-in for the box program (osascript, PowerShell): it keeps what it was given and answers what the
    test says. The secret it is given is never printed."""

    def __init__(self, out: bytes = b"", answers: list = None) -> None:
        self.calls: list = []
        self.answers = list(answers or [])
        self.out = out

    async def __call__(self, *argv, **kw):
        call = {"argv": list(argv), "env": dict(kw.get("env") or {}), "stdin": b""}
        self.calls.append(call)
        box = self

        class Proc:
            returncode = 0

            async def communicate(self, data=None):
                call["stdin"] = data or b""
                return (box.answers.pop(0) if box.answers else box.out), b""

            def kill(self):
                pass

        return Proc()


class FakeImage:
    """The picture the qrcode package would draw: it is written into the stream it is given (in memory), never
    to a file."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.stream = None

    def save(self, stream, format=None):
        self.stream = stream
        stream.write(self.data)


class UriTests(unittest.TestCase):
    """The URI an authenticator app reads (the otpauth key-uri form)."""

    def test_the_uri_is_the_form_the_apps_read(self):
        self.assertEqual(enroll.otpauth_uri(KEY), URI)
        self.assertTrue(URI.startswith("otpauth://totp/Hermes%20Tether?secret="))
        self.assertIn("&issuer=Hermes%20Tether&algorithm=SHA1&digits=6&period=30", URI)

    def test_the_uri_holds_the_key_in_base32_without_padding(self):
        uri = enroll.otpauth_uri(KEY)
        self.assertIn("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&", uri)
        self.assertNotIn("=", uri.split("secret=")[1].split("&")[0])
        self.assertNotIn(" ", uri)

    def test_the_uri_names_one_entry_for_every_machine(self):
        uri = enroll.otpauth_uri("abcd-efgh", "mac (studio) & co")
        self.assertTrue(uri.startswith("otpauth://totp/Hermes%20Tether?secret="), uri)
        self.assertIn("secret=ABCDEFGH&", uri)
        self.assertIn("&issuer=Hermes%20Tether&", uri)
        self.assertNotIn("mac", uri)
        self.assertNotIn(" ", uri)

    def test_the_uri_of_the_key_the_store_makes(self):
        """The key the sealed store makes (base32 in groups of four) becomes the secret, without the groups."""
        pending = ss.PendingSetup(bytes(range(20)))
        text = pending.key_text()
        uri = enroll.otpauth_uri(text)
        self.assertIn("secret=" + text.replace(" ", "") + "&", uri)
        self.assertEqual(text.replace(" ", ""), base64.b32encode(bytes(range(20))).decode().rstrip("="))


class MacScriptTests(unittest.TestCase):
    """The JXA that draws the code on a Mac (never run here: the text is read, not executed)."""

    def test_the_script_draws_the_code_with_the_system(self):
        script = enroll.MacUI.qr_script(the_qr(), ("Cancel", "I added it"))
        self.assertIn("CIQRCodeGenerator", script)
        self.assertIn("inputMessage", script)
        self.assertIn("inputCorrectionLevel", script)
        self.assertIn('"M"', script)
        self.assertIn("CIContext", script)
        self.assertIn("CGContextSetInterpolation", script)   # nearest neighbour: sharp squares
        self.assertIn("ScaleCTM", script)                     # the code stays upright in the bitmap
        self.assertIn("NSAlert", script)
        self.assertIn("setAccessoryView", script)
        self.assertIn("activateIgnoringOtherApps", script)
        self.assertNotIn("@@", script, "a placeholder was left in the script")

    def test_the_script_holds_the_uri_the_key_and_the_buttons(self):
        script = enroll.MacUI.qr_script(the_qr(), ("Cancel", "I added it"))
        self.assertIn(URI, script)
        self.assertIn(KEY, script, "the key under the code is not in the script")
        self.assertIn("Can't scan? Type this key: " + KEY, script)
        self.assertIn("Cancel", script)
        self.assertIn("I added it", script)
        self.assertIn("Hermes Tether", script)

    def test_the_script_line_up(self):
        """A light syntax check of the script text: its brackets and its strings close (osacompile, the real
        check, needs Apple Events and cannot run here)."""
        script = enroll.MacUI.qr_script(the_qr(), ("Cancel", "I added it"))
        self.assertTrue(_js_balanced(script), "the script text does not line up")
        self.assertTrue(script.rstrip().endswith("}"), "the script does not end with its function")

    def test_the_script_compiles(self):
        """The JXA compiles (osacompile only compiles; it shows nothing). Skipped here: this environment has no
        Apple Events; set TETHER_COMPILE_JXA=1 where osascript may run."""
        if not os.environ.get("TETHER_COMPILE_JXA"):
            self.skipTest("osacompile is not run in this environment (set TETHER_COMPILE_JXA=1 to compile it)")
        script = enroll.MacUI.qr_script(the_qr(), ("Cancel", "I added it"))
        out = Path("/tmp/tether-qr-check.scpt")
        done = subprocess.run(["/usr/bin/osacompile", "-l", "JavaScript", "-o", str(out), "-e", script],
                              capture_output=True, timeout=60)
        self.assertEqual(done.returncode, 0, "the JXA does not compile")


class MacBoxTests(unittest.TestCase):
    """The Mac box: the code on stdin, the key box when the code cannot be drawn."""

    def test_the_code_goes_on_stdin_and_nowhere_else(self):
        box = FakeBox(out=b"I added it\n")
        with mock.patch("asyncio.create_subprocess_exec", box):
            ans = run(enroll.MacUI("mac").ask_qr(the_qr(), ("Cancel", "I added it")))
        self.assertEqual(ans.button, "I added it")
        self.assertEqual(len(box.calls), 1)
        self.assertEqual(box.calls[0]["argv"], ["/usr/bin/osascript", "-l", "JavaScript", "-"])
        stdin = box.calls[0]["stdin"].decode("utf-8")
        self.assertIn(URI, stdin)
        self.assertNotIn(URI, " ".join(box.calls[0]["argv"]))
        for value in box.calls[0]["env"].values():
            self.assertNotIn(URI, value)
            self.assertNotIn(KEY, value)

    def test_the_key_box_is_the_fallback_when_the_code_box_says_nothing(self):
        for out in (b"", b"\n", b"something else\n"):
            with self.subTest(out=out):
                box = FakeBox(out=out)
                with mock.patch("asyncio.create_subprocess_exec", box):
                    ans = run(enroll.MacUI("mac").ask_qr(the_qr(), ("Cancel", "I added it")))
                self.assertEqual(len(box.calls), 2, "the key box was not shown after the code box failed")
                self.assertEqual(box.calls[1]["argv"], ["/usr/bin/osascript", "-"])
                script = box.calls[1]["stdin"].decode("utf-8")
                self.assertIn("display dialog", script)
                self.assertIn(f"3. Key: {KEY}", script)
                self.assertIsNone(ans.button)

    def test_a_deliberate_cancel_is_not_a_fallback(self):
        box = FakeBox(out=b"Cancel\n")
        with mock.patch("asyncio.create_subprocess_exec", box):
            ans = run(enroll.MacUI("mac").ask_qr(the_qr(), ("Cancel", "I added it")))
        self.assertEqual(len(box.calls), 1, "a box was shown again after the person cancelled")
        self.assertIsNone(ans.button)

    def test_the_fallback_is_logged_without_a_value(self):
        records: list = []

        class Grab(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        root = logging.getLogger()
        handler, level = Grab(level=logging.DEBUG), root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, level)
        box = FakeBox(out=b"")
        with mock.patch("asyncio.create_subprocess_exec", box):
            run(enroll.MacUI("mac").ask_qr(the_qr(), ("Cancel", "I added it")))
        said = [r for r in records if "key box" in r]
        self.assertEqual(len(said), 1, "the fallback was not logged once")
        for text in records:
            self.assertNotIn(KEY, text, "the key reached a log")
            self.assertNotIn(URI, text, "the URI reached a log")


class WindowsBoxTests(unittest.TestCase):
    """The PC box: the picture in the box when the qrcode package is there, the key box when it is not."""

    def test_the_pc_draws_the_code_when_the_package_is_there(self):
        image = FakeImage(PNG)
        fake = types.SimpleNamespace(make=lambda uri, **kw: image)
        box = FakeBox(out=json.dumps({"button": "I added it", "text": ""}).encode())
        with mock.patch.dict(sys.modules, {"qrcode": fake}), mock.patch("asyncio.create_subprocess_exec", box):
            ans = run(enroll.WindowsUI("pc").ask_qr(the_qr(), ("Cancel", "I added it")))
        self.assertEqual(ans.button, "I added it")
        payload = json.loads(box.calls[0]["stdin"].decode("utf-8"))
        self.assertEqual(base64.b64decode(payload["image"]), PNG)
        self.assertIn(f"Can't scan? Type this key: {KEY}", payload["text"])
        self.assertNotIn(URI, " ".join(box.calls[0]["argv"]), "the URI reached the arguments")
        self.assertIsNotNone(image.stream, "the picture was not written into memory")
        self.assertFalse(isinstance(image.stream, (str, bytes)), "the picture was written to a file")

    def test_the_pc_keeps_the_key_box_without_the_package(self):
        box = FakeBox(out=b"")
        with mock.patch.dict(sys.modules, {"qrcode": None}), mock.patch("asyncio.create_subprocess_exec", box):
            ans = run(enroll.WindowsUI("pc").ask_qr(the_qr(), ("Cancel", "I added it")))
        self.assertIsNone(ans.button)
        payload = json.loads(box.calls[0]["stdin"].decode("utf-8"))
        self.assertNotIn("image", payload)
        self.assertIn(f"3. Key: {KEY}", payload["text"])

    def test_the_pc_box_knows_a_picture(self):
        """The box script shows the picture it is given (the key stays visible under it)."""
        self.assertIn("PictureBox", enroll.WINDOWS_BOX_SCRIPT)
        self.assertIn("FromBase64String", enroll.WINDOWS_BOX_SCRIPT)


class SetupFlowTests(unittest.TestCase):
    """The setup itself: the code box is shown, and the first code still decides before anything is saved."""

    def setUp(self):
        self.d = temp_dir(self, "hp-enroll-qr-")
        self.clock = Clock()

    def flow(self, person: Person) -> enroll.Enrollment:
        store = ss.SeedStore(self.d, seal(), clock=self.clock)
        return enroll.Enrollment(self.d, "mac", store, person, clock=self.clock, settle_s=0)

    def test_the_setup_shows_the_code_with_the_key_under_it(self):
        p = Person(self.clock)
        res = run(self.flow(p).setup())
        self.assertTrue(res.ok, "the setup a person completed did not finish")
        self.assertTrue(p.qrs, "the setup did not show the code to scan")
        qr = p.qrs[0]
        self.assertEqual(qr.uri, enroll.otpauth_uri(qr.key_text))
        self.assertTrue(qr.uri.startswith("otpauth://totp/Hermes%20Tether?secret="))
        self.assertEqual(qr.fallback, f"Can't scan? Type this key: {qr.key_text}")
        self.assertIn("scan a QR code", qr.text)

    def test_a_mis_scanned_key_still_saves_nothing(self):
        """The first-code check is unchanged: a key that was scanned or typed wrong saves nothing."""
        p = Person(self.clock, confirm="wrong")
        res = run(self.flow(p).setup())
        self.assertFalse(res.ok)
        self.assertIsNone(seed_in(self.d), "a key was stored although the first code did not match")
        self.assertEqual(enroll.state(ss.SeedStore(self.d, seal(), clock=self.clock)), enroll.OFF)


def _js_balanced(text: str) -> bool:
    """The brackets of a script line up and its strings close (a light check of a script that is not run)."""
    depth = {"(": 0, "[": 0, "{": 0}
    pairs = {")": "(", "]": "[", "}": "{"}
    quote = None
    escaped = False
    line = 0
    while line < len(text):
        ch = text[line]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            line += 1
            continue
        if ch == "/" and line + 1 < len(text) and text[line + 1] == "/":
            while line < len(text) and text[line] != "\n":
                line += 1
            continue
        if ch in "\"'":
            quote = ch
        elif ch in depth:
            depth[ch] += 1
        elif ch in pairs:
            depth[pairs[ch]] -= 1
            if depth[pairs[ch]] < 0:
                return False
        line += 1
    return quote is None and not any(depth.values())


if __name__ == "__main__":
    unittest.main()


class QrBoxCloseTests(unittest.TestCase):
    def test_a_box_closed_without_a_button_is_a_cancel(self):
        """A modal answer that is no button (the session stopped or aborted) must never read as 'I added it'."""
        tail = enroll.JXA_QR_SCRIPT.split("Number(alert.runModal);", 1)[1]
        self.assertNotIn("return buttons[0]", tail, "a box closed without a button counts as the way on")
        self.assertIn('return "";', tail, "a box closed without a button is not a cancel")


class QrScriptRunsTests(unittest.TestCase):
    def test_the_core_image_context_is_made_without_a_null_options_argument(self):
        """JXA bridges null to NSNull: contextWithOptions(null) raises '-[NSNull objectForKey:]' and the box never
        shows (seen on macOS 27.2.1 in the first real setup run)."""
        self.assertNotIn("contextWithOptions(null)", enroll.JXA_QR_SCRIPT, "the code box crashes before it shows")
        self.assertIn("$.CIContext.context", enroll.JXA_QR_SCRIPT, "the code box makes no drawing context")


class QrBoxAnswerTests(unittest.TestCase):
    def test_the_box_is_run_by_property_access_not_called(self):
        """In JXA a no-argument method runs when it is named; 'alert.runModal()' showed the box and then threw
        'is not a function', so the person's click was lost and the key box came up after it (first real run)."""
        self.assertNotIn("runModal()", enroll.JXA_QR_SCRIPT, "the box's answer is thrown away after the click")
        self.assertIn("alert.runModal;", enroll.JXA_QR_SCRIPT.replace("Number(alert.runModal)", "alert.runModal;"),
                      "the box is never run")
