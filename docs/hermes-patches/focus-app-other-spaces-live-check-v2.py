"""Live check v2: Space round trip + which window a capture would target (metadata only, no screenshot)."""
import os, sys, time, types, json
sys.path.insert(0, os.path.expanduser("~/.hermes/hermes-agent"))
os.environ.setdefault("HERMES_CUA_DRIVER_CMD", "/Applications/CuaDriver.app/Contents/MacOS/cua-driver")
import tools.computer_use.cua_backend_capture as orig
from tools.computer_use.cua_backend import CuaDriverBackend
patched = types.ModuleType("patched"); patched.__dict__["__name__"] = orig.__name__
exec(compile(open(sys.argv[1]).read(), "patched.py", "exec"), patched.__dict__)
orig._CaptureMixin.focus_app = patched._CaptureMixin.focus_app
orig._CaptureMixin._windows_on_any_space = patched._CaptureMixin._windows_on_any_space
b = CuaDriverBackend(permission_mode="standard"); b.start()
def space():
    return (b.call_tool("list_windows", {"on_screen_only": False}).get("structuredContent") or {}).get("current_space_id")
def where():
    rows = (b.call_tool("list_windows", {"on_screen_only": False}).get("structuredContent") or {}).get("windows") or []
    out = {}
    for w in rows:
        if w.get("app_name") in ("Hermes", "Claude") and w.get("space_ids"):
            out.setdefault(w["app_name"], set()).update(w["space_ids"])
    return out
def targets(label):
    ws = b.list_windows()
    old = orig._select_capture_target(ws, app_requested=False)
    new = patched._select_capture_target(ws, app_requested=False)
    print(f"  capture target {label}: old -> {old['app_name']} {old['window_id']} title={old['title']!r} | "
          f"new -> {new['app_name']} {new['window_id']} title={new['title']!r}", flush=True)
def show(label, r):
    print(f"{label}: ok={r.ok} code={r.code} verified={r.verified} effect={r.effect} escalation={r.escalation} "
          f"status={(r.meta or {}).get('status')} driver_verdict={(r.meta or {}).get('driver_verdict')}", flush=True)
try:
    cur, w = space(), where()
    home = next(a for a, sp in w.items() if cur in sp); other = next(a for a, sp in w.items() if cur not in sp)
    print("start space", cur, "home", home, "other", other, flush=True)
    targets("at start")
    show(f"raise {other}", b.focus_app(other, raise_window=True)); time.sleep(1.5); targets(f"on {other}'s Space")
    show(f"raise {home}", b.focus_app(home, raise_window=True)); time.sleep(1.5); targets(f"on {home}'s Space")
    print("end space", space(), "(start", cur, ")", flush=True)
finally:
    b.stop()
