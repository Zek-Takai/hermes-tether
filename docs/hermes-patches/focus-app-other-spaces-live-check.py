"""Live check of the focus_app patch on the real Mac Spaces (no screenshots: Space ids only)."""
import os, sys, time, types, json
sys.path.insert(0, os.path.expanduser("~/.hermes/hermes-agent"))
os.environ.setdefault("HERMES_CUA_DRIVER_CMD", "/Applications/CuaDriver.app/Contents/MacOS/cua-driver")
import tools.computer_use.cua_backend_capture as orig
from tools.computer_use.cua_backend import CuaDriverBackend

patched = types.ModuleType("cua_backend_capture_patched")
patched.__dict__["__name__"] = orig.__name__
src = open(sys.argv[1]).read()
exec(compile(src, "patched_cua_backend_capture.py", "exec"), patched.__dict__)
OLD_FOCUS = orig._CaptureMixin.focus_app

def use(new):
    orig._CaptureMixin.focus_app = patched._CaptureMixin.focus_app if new else OLD_FOCUS
    orig._CaptureMixin._windows_on_any_space = patched._CaptureMixin._windows_on_any_space

b = CuaDriverBackend(permission_mode="standard")
b.start()

def spaces():
    out = b.call_tool("list_windows", {"on_screen_only": False})
    sc = out.get("structuredContent") or {}
    rows = sc.get("windows") or []
    where = {}
    for w in rows:
        if w.get("app_name") in ("Hermes", "Claude") and w.get("space_ids"):
            where.setdefault(w["app_name"], set()).update(w["space_ids"])
    return sc.get("current_space_id"), {k: sorted(v) for k, v in where.items()}

def show(label, r):
    meta = json.dumps(getattr(r, "meta", {}) or {}, default=str)[:600]
    print(f"{label}: ok={r.ok} code={getattr(r, 'code', None)} msg={r.message!r} meta={meta}", flush=True)

try:
    cur, where = spaces()
    print("start: current space", cur, "apps on spaces", where, flush=True)
    here = [a for a, sp in where.items() if cur in sp]
    away = [a for a, sp in where.items() if cur not in sp]
    if not here or not away:
        print("need one of Hermes/Claude on this Space and the other elsewhere; stopping"); sys.exit(2)
    home, other = here[0], away[0]
    use(False); show(f"OLD focus_app({other!r}, raise)", b.focus_app(other, raise_window=True))
    use(True);  show(f"NEW focus_app({other!r}, no raise)", b.focus_app(other, raise_window=False))
    use(True);  r = b.focus_app(other, raise_window=True); show(f"NEW focus_app({other!r}, raise)", r)
    time.sleep(1.5); print("after raise: current space", spaces()[0], flush=True)
    use(True);  show(f"NEW focus_app({home!r}, raise) back", b.focus_app(home, raise_window=True))
    time.sleep(1.5); print("end: current space", spaces()[0], "(start was", cur, ")", flush=True)
finally:
    use(False)
    b.stop()
