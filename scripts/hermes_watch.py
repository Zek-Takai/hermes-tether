#!/usr/bin/env python3
"""Maintainers' watcher: does a Hermes release change what Tether wraps, copies, overrides or depends on by name?

Not shipped in the plugin, and never run on a user's machine (DESIGN D72). Run it on a Hermes source folder
before telling people to update Hermes:

    scripts/hermes_watch.py <hermes-source>                  # prints nothing when all match
    scripts/hermes_watch.py <hermes-source> --write-baseline # after Tether was verified against that source

The watch list is derived from the plugin's own code (plugin/): every name imported from a Hermes module
(``from tools... import x``, ``import tools.environments.local as L`` then ``L.x``, ``from agent... import``,
``from gateway...``, ``from hermes_cli...``, ``hermes_constants``, ``model_tools``, ...), Hermes names looked up by
string (``sys.modules.get("model_tools")`` then ``getattr(m, "x")``, ``("module", "name")`` pairs), and for every
plugin class that subclasses a Hermes class, the Hermes methods it overrides and the ones it calls on ``self``
(this is how LockedEnvironment's copy of ``LocalEnvironment._run_bash`` and everything that copy calls is covered).
The spawn surface is added too, because the session lock only covers processes that go through the overridden
methods: every method of those Hermes classes that starts a process, and every function in Hermes's ``tools``
package that calls ``_run_bash`` or ``_spawn_long_lived`` on an environment. A new way to start a process there
shows up as ``not in baseline``.

Each name gets a normalized hash of its definition in the Hermes source: the AST without docstrings, comments or
formatting, so only a real code change shows. A class's hash covers its bases, decorators, member names and
``__init__``; the members Tether uses are separate entries. Output: nothing when every name matches the baseline;
otherwise one line per name, ``changed: <name>``, ``missing: <name>`` or ``not in baseline: <name>`` (a name Tether
now uses that the baseline does not know: verify it, then write the baseline again). Exit 0 when nothing printed,
1 when something did, 2 on an error. Standard library only; no network.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional

HERE = Path(__file__).resolve().parent
DEFAULT_BASELINE = HERE / "hermes_watch_baseline.json"
DEFAULT_PLUGIN = HERE.parent / "plugin"
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SKIP_ATTRS = {"__file__", "__name__", "__spec__", "__code__", "__dict__", "__path__", "__loader__", "__doc__",
               "__class__", "__module__", "__qualname__"}


# ---------- the Hermes source ----------

def hermes_top_names(root: Path) -> set[str]:
    """Top-level import names the Hermes source folder provides (packages and modules)."""
    out = set()
    for p in root.iterdir():
        if p.name.startswith((".", "_")) or p.name in ("venv", "node_modules", "tests"):
            continue
        if p.is_dir() and (p / "__init__.py").is_file():
            out.add(p.name)
        elif p.suffix == ".py" and _IDENT.match(p.stem):
            out.add(p.stem)
    return out


class Source:
    """One Hermes source folder, parsed lazily, module by module."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._trees: dict[str, Optional[ast.Module]] = {}

    def module_file(self, dotted: str) -> Optional[Path]:
        base = self.root.joinpath(*dotted.split("."))
        if (base / "__init__.py").is_file():
            return base / "__init__.py"
        if base.with_suffix(".py").is_file():
            return base.with_suffix(".py")
        return None

    def is_package(self, dotted: str) -> bool:
        return (self.root.joinpath(*dotted.split(".")) / "__init__.py").is_file()

    def tree(self, dotted: str) -> Optional[ast.Module]:
        if dotted not in self._trees:
            path = self.module_file(dotted)
            try:
                self._trees[dotted] = ast.parse(path.read_text(encoding="utf-8")) if path else None
            except (OSError, SyntaxError, UnicodeDecodeError):
                self._trees[dotted] = None
        return self._trees[dotted]

    def split(self, dotted: str) -> tuple[Optional[str], list[str]]:
        """(the longest prefix that is a module of this source, the rest)."""
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            mod = ".".join(parts[:i])
            if self.module_file(mod):
                return mod, parts[i:]
        return None, parts

    def _absolute(self, module: str, node: ast.ImportFrom) -> str:
        if not node.level:
            return node.module or ""
        base = module.split(".")
        if not self.is_package(module):
            base = base[:-1]
        base = base[:len(base) - (node.level - 1)] if node.level > 1 else base
        return ".".join([*base, *([node.module] if node.module else [])])

    def top(self, module: str, name: str, depth: int = 0) -> Optional[tuple[str, ast.AST, str]]:
        """(kind, node, module) for a name defined at the top of module: def, class, assignment, or followed
        through a re-export import. None when missing."""
        tree = self.tree(module)
        if tree is None or depth > 8:
            return None
        found = None
        for node in _top_level(tree.body):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                found = ("function", node, module)
            elif isinstance(node, ast.ClassDef) and node.name == name:
                found = ("class", node, module)
            elif isinstance(node, ast.Assign) and any(_binds(t, name) for t in node.targets):
                found = ("value", node, module)
            elif isinstance(node, ast.AnnAssign) and _binds(node.target, name):
                found = ("value", node, module)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if (alias.asname or alias.name) == name and alias.name != "*":
                        target = self._absolute(module, node)
                        hit = self.top(target, alias.name, depth + 1) if self.module_file(target) else None
                        if hit is None and self.module_file(f"{target}.{alias.name}"):
                            hit = ("module", self.tree(f"{target}.{alias.name}"), f"{target}.{alias.name}")
                        found = hit or found
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname == name and self.module_file(alias.name):
                        found = ("module", self.tree(alias.name), alias.name)
        if found is None and self.module_file(f"{module}.{name}"):
            found = ("module", self.tree(f"{module}.{name}"), f"{module}.{name}")
        return found

    def member(self, module: str, cls: ast.ClassDef, name: str, depth: int = 0) -> Optional[tuple[str, ast.AST, str]]:
        """A member of a class, looked up through its bases (as Python's attribute lookup would, in order)."""
        if depth > 12:
            return None
        for node in cls.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return "function", node, module
            if isinstance(node, ast.ClassDef) and node.name == name:
                return "class", node, module
            if isinstance(node, ast.Assign) and any(_binds(t, name) for t in node.targets):
                return "value", node, module
            if isinstance(node, ast.AnnAssign) and _binds(node.target, name):
                return "value", node, module
        for base in cls.bases:
            hit = self.base_class(module, base)
            if hit is not None:
                found = self.member(hit[2], hit[1], name, depth + 1)
                if found is not None:
                    return found
        return None

    def base_class(self, module: str, expr: ast.expr) -> Optional[tuple[str, ast.ClassDef, str]]:
        dotted = _dotted(expr)
        if not dotted:
            return None
        head, *rest = dotted.split(".")
        hit = self.top(module, head)
        for part in rest:
            if hit is None:
                return None
            if hit[0] == "module":
                hit = self.top(hit[2], part)
            elif hit[0] == "class":
                hit = self.member(hit[2], hit[1], part)
            else:
                return None
        return hit if hit is not None and hit[0] == "class" else None

    def resolve(self, dotted: str) -> Optional[tuple[str, ast.AST, str]]:
        module, rest = self.split(dotted)
        if module is None:
            return None
        if not rest:
            return "module", self.tree(module), module
        hit = self.top(module, rest[0])
        for part in rest[1:]:
            if hit is None:
                return None
            if hit[0] == "class":
                hit = self.member(hit[2], hit[1], part)
            elif hit[0] == "module":
                hit = self.top(hit[2], part)
            else:
                return None
        return hit


def _top_level(body: list) -> Iterable[ast.stmt]:
    """Top-level statements, including those inside module-level if/try blocks (version shims)."""
    for node in body:
        if isinstance(node, ast.If):
            yield from _top_level(node.body)
            yield from _top_level(node.orelse)
        elif isinstance(node, ast.Try):
            yield from _top_level(node.body)
            for h in node.handlers:
                yield from _top_level(h.body)
            yield from _top_level(node.orelse)
            yield from _top_level(node.finalbody)
        else:
            yield node


def _binds(target: ast.expr, name: str) -> bool:
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_binds(t, name) for t in target.elts)
    return False


def _dotted(expr: ast.expr) -> str:
    parts = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if isinstance(expr, ast.Name):
        parts.append(expr.id)
        return ".".join(reversed(parts))
    return ""


# ---------- normalized hashes ----------

def _strip_docstrings(node: ast.AST) -> ast.AST:
    node = copy.deepcopy(node)
    for sub in ast.walk(node):
        body = getattr(sub, "body", None)
        if isinstance(sub, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and body \
                and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                and isinstance(body[0].value.value, str):
            sub.body = body[1:] or [ast.Pass()]
    return node


def _canon(node: object) -> str:
    """The AST as text, the same on every Python version that parses it (ast.dump's own output changed between
    3.11 and 3.13: empty fields, new fields such as type_params). Empty and None fields are left out."""
    if isinstance(node, ast.AST):
        parts = []
        for field in node._fields:
            if field in ("ctx", "type_comment", "kind"):
                continue
            value = getattr(node, field, None)
            if value is None or value == []:
                continue
            parts.append(f"{field}={_canon(value)}")
        return f"{type(node).__name__}({','.join(parts)})"
    if isinstance(node, list):
        return "[" + ",".join(_canon(x) for x in node) + "]"
    return repr(node)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:20]


def fingerprint(hit: Optional[tuple[str, ast.AST, str]]) -> str:
    if hit is None:
        return "missing"
    kind, node, _module = hit
    if kind == "module":
        return "module"                      # a namespace: what Tether uses from it is listed by name
    if kind == "class":
        node = _strip_docstrings(node)
        members = sorted(getattr(n, "name", "") or ",".join(_names(n)) for n in node.body
                         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Assign,
                                           ast.AnnAssign)))
        init = next((n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and n.name == "__init__"), None)
        parts = [_canon(b) for b in node.bases] + [_canon(k) for k in node.keywords] \
            + [_canon(d) for d in node.decorator_list] + members + [_canon(init) if init else ""]
        return _digest("class\0" + "\0".join(parts))
    return _digest(kind + "\0" + _canon(_strip_docstrings(node)))


def _names(node: ast.AST) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [getattr(node, "target", None)]
    out = []
    for t in targets:
        if isinstance(t, ast.Name):
            out.append(t.id)
        elif isinstance(t, (ast.Tuple, ast.List)):
            out.extend(e.id for e in t.elts if isinstance(e, ast.Name))
    return out


# ---------- the watch list, from the plugin's own code ----------

def _is_hermes(dotted: str, tops: set[str]) -> bool:
    return bool(dotted) and dotted.split(".")[0] in tops


def derive_names(plugin: Path, source: Source) -> list[str]:
    """Every Hermes name the plugin's code uses (see the module docstring)."""
    tops = hermes_top_names(source.root)
    names: set[str] = set()
    subclass_jobs: list[tuple[ast.ClassDef, list[str]]] = []
    for path in sorted(Path(plugin).rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        aliases: dict[str, str] = {}             # a local name -> the Hermes module or name it stands for
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and not node.level and _is_hermes(node.module or "", tops):
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    full = f"{node.module}.{alias.name}"
                    names.add(full)
                    aliases[alias.asname or alias.name] = full
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if _is_hermes(alias.name, tops):
                        names.add(alias.name)
                        if alias.asname:
                            aliases[alias.asname] = alias.name
                        else:
                            aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]
            elif isinstance(node, ast.Assign):
                # model_tools = sys.modules.get("model_tools"), and tuple forms of it
                pairs = []
                if isinstance(node.value, ast.Tuple) and len(node.targets) == 1 \
                        and isinstance(node.targets[0], ast.Tuple):
                    pairs = list(zip(node.targets[0].elts, node.value.elts))
                elif len(node.targets) == 1:
                    pairs = [(node.targets[0], node.value)]
                for target, value in pairs:
                    mod = _modules_get(value)
                    if isinstance(target, ast.Name) and mod and _is_hermes(mod, tops):
                        names.add(mod)
                        aliases[target.id] = mod
            elif isinstance(node, ast.Tuple) and len(node.elts) >= 2 \
                    and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts[:2]):
                mod, attr = node.elts[0].value, node.elts[1].value
                if _is_hermes(mod, tops) and source.module_file(mod) and _IDENT.match(attr):
                    names.add(f"{mod}.{attr}")          # ("agent.delegation_context", "is_delegated_...") pairs
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr not in _SKIP_ATTRS:
                dotted = _dotted(node)
                head = dotted.split(".")[0] if dotted else ""
                if head in aliases:
                    full = aliases[head] + dotted[len(head):]
                    hit = source.resolve(aliases[head])
                    if hit is not None and hit[0] in ("module", "class"):
                        names.add(_trim(full, source))
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" \
                    and len(node.args) >= 2 and isinstance(node.args[0], ast.Name) \
                    and node.args[0].id in aliases and isinstance(node.args[1], ast.Constant) \
                    and isinstance(node.args[1].value, str) and _IDENT.match(node.args[1].value):
                names.add(f"{aliases[node.args[0].id]}.{node.args[1].value}")
            elif isinstance(node, ast.ClassDef):
                bases = [aliases.get(_dotted(b).split(".")[0], "") + _dotted(b)[len(_dotted(b).split(".")[0]):]
                         for b in node.bases if _dotted(b).split(".")[0] in aliases]
                if bases:
                    subclass_jobs.append((node, bases))
    hermes_classes: list[tuple[str, ast.ClassDef, str]] = []
    for cls, bases in subclass_jobs:
        own = {n.name for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        used = set(own)
        for sub in ast.walk(cls):
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "self":
                used.add(sub.attr)
        for base in bases:
            hit = source.resolve(base)
            if hit is None or hit[0] != "class":
                continue
            hermes_classes.append(hit)
            for name in sorted(used):
                found = source.member(hit[2], hit[1], name)
                if found is not None and found[0] in ("function", "value"):
                    names.add(f"{base}.{name}")
    names |= spawn_surface(source, hermes_classes)
    return sorted(n for n in names if n.split(".")[-1] not in _SKIP_ATTRS)


_SPAWN_DOTTED = {"subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
                 "subprocess.check_output", "os.system", "os.posix_spawn", "os.posix_spawnp", "os.execv", "os.execve",
                 "os.execvp", "os.spawnv", "os.spawnve", "pty.spawn", "pty.fork", "asyncio.create_subprocess_exec",
                 "asyncio.create_subprocess_shell"}
_SPAWN_ATTRS = {"_run_bash", "_spawn_long_lived", "Popen"}
_ENV_SPAWN = {"_run_bash", "_spawn_long_lived"}         # an environment's own process starts, called from outside


def _spawns(node: ast.AST, attrs: set[str] = _SPAWN_ATTRS, dotted_calls: bool = True) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            dotted = _dotted(sub.func)
            if (dotted_calls and dotted in _SPAWN_DOTTED) \
                    or (isinstance(sub.func, ast.Attribute) and sub.func.attr in attrs):
                return True
    return False


def spawn_surface(source: Source, classes: list[tuple[str, ast.ClassDef, str]]) -> set[str]:
    """Where Hermes starts processes for the environments Tether subclasses (see the module docstring)."""
    out: set[str] = set()
    seen: set[tuple[str, str]] = set()
    todo = [(hit[2], hit[1]) for hit in classes]
    while todo:
        module, cls = todo.pop()
        if (module, cls.name) in seen:
            continue
        seen.add((module, cls.name))
        for node in cls.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _spawns(node):
                out.add(f"{module}.{cls.name}.{node.name}")
        for base in cls.bases:
            hit = source.base_class(module, base)
            if hit is not None:
                todo.append((hit[2], hit[1]))
    tools_dir = source.root / "tools"
    for path in sorted(tools_dir.rglob("*.py")) if tools_dir.is_dir() else []:
        if "__pycache__" in path.parts or "tests" in path.parts:
            continue
        module = ".".join(path.relative_to(source.root).with_suffix("").parts)
        if module.endswith(".__init__"):
            module = module[: -len(".__init__")]
        tree = source.tree(module)
        for node in tree.body if tree is not None else []:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _spawns(node, _ENV_SPAWN, False):
                out.add(f"{module}.{node.name}")
            elif isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                            and _spawns(sub, _ENV_SPAWN, False):
                        out.add(f"{module}.{node.name}.{sub.name}")
    return out


def _modules_get(value: ast.expr) -> str:
    """'m' for sys.modules.get("m") / sys.modules["m"] / importlib.import_module("m")."""
    if isinstance(value, ast.Call) and _dotted(value.func) in ("sys.modules.get", "importlib.import_module") \
            and value.args and isinstance(value.args[0], ast.Constant) and isinstance(value.args[0].value, str):
        return value.args[0].value
    if isinstance(value, ast.Subscript) and _dotted(value.value) == "sys.modules" \
            and isinstance(value.slice, ast.Constant) and isinstance(value.slice.value, str):
        return value.slice.value
    return ""


def _trim(dotted: str, source: Source) -> str:
    """The longest prefix of a used attribute chain that names something in the source (L.x.y -> L.x when x is a
    function: y is an attribute of what it returns)."""
    parts = dotted.split(".")
    for i in range(len(parts), 0, -1):
        cand = ".".join(parts[:i])
        hit = source.resolve(cand)
        if hit is not None:
            return cand
    return dotted


# ---------- baseline ----------

def describe(root: Path) -> dict:
    def git(*args: str) -> str:
        try:
            return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30,
                                  check=False).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    return {"commit": git("rev-parse", "HEAD"),
            "version": git("describe", "--tags", "--exact-match", "HEAD") or git("describe", "--tags")}


def compute(names: Iterable[str], source: Source) -> dict[str, str]:
    return {n: fingerprint(source.resolve(n)) for n in names}


def compare(baseline: dict, now: dict[str, str], derived: Optional[list[str]]) -> list[str]:
    lines = []
    for name, want in sorted(baseline.items()):
        got = now.get(name, "missing")
        if got == want:
            continue
        lines.append(f"missing: {name}" if got == "missing" else f"changed: {name}")
    for name in sorted(set(derived or ()) - set(baseline)):
        lines.append(f"not in baseline: {name}")
    return lines


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Does a Hermes source change what Tether wraps? (maintainers only)")
    ap.add_argument("hermes_source", help="a Hermes source folder (a checkout of hermes-agent)")
    ap.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    ap.add_argument("--plugin", default=str(DEFAULT_PLUGIN), help="Tether's plugin folder (the watch list's source)")
    ap.add_argument("--write-baseline", action="store_true",
                    help="record this source as verified (only after Tether was checked against it)")
    args = ap.parse_args(argv)
    root = Path(args.hermes_source)
    if not (root.is_dir() and hermes_top_names(root)):
        print(f"hermes watch: {root} is not a Hermes source folder", file=sys.stderr)
        return 2
    source = Source(root)
    plugin = Path(args.plugin)
    derived = derive_names(plugin, source) if plugin.is_dir() else None
    if args.write_baseline:
        if derived is None:
            print(f"hermes watch: no plugin folder at {plugin}", file=sys.stderr)
            return 2
        data = {"what": "normalized AST hashes of the Hermes names Tether uses (scripts/hermes_watch.py)",
                "hermes": describe(root), "names": compute(derived, source)}
        Path(args.baseline).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
        return 0
    try:
        base = json.loads(Path(args.baseline).read_text())["names"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"hermes watch: the baseline {args.baseline} could not be read ({type(e).__name__})", file=sys.stderr)
        return 2
    lines = compare(base, compute(base, source), derived)
    for line in lines:
        print(line)
    return 1 if lines else 0


if __name__ == "__main__":
    sys.exit(main())
