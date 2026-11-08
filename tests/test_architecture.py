"""Layering rule: ``backend/`` (the HTTP API) may import ``app/`` (the core), never the reverse.

Why it matters: the detection engine, storage and user logic are also used by the CLI, the demo
event generator and (later) the sensor. If ``app/`` pulled in FastAPI or ``backend/``, none of
those could use it without dragging the web stack along.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB_FRAMEWORKS = {"fastapi", "starlette", "uvicorn"}


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def test_core_never_imports_the_api_layer_or_a_web_framework():
    offenders = []
    for path in (ROOT / "app").rglob("*.py"):
        for module in imported_modules(path):
            top = module.split(".")[0]
            if top == "backend" or top in WEB_FRAMEWORKS:
                offenders.append(f"{path.relative_to(ROOT)} imports {module}")
    assert not offenders, "\n".join(offenders)


def test_core_modules_live_in_app_and_api_modules_in_backend():
    core = {"models", "config", "db", "storage", "passwords", "manage"}
    api = {"main", "auth", "security", "ratelimit", "deps"}
    assert {p.stem for p in (ROOT / "app").glob("*.py")} >= core
    assert not core & {p.stem for p in (ROOT / "backend").glob("*.py")}
    assert {p.stem for p in (ROOT / "backend").glob("*.py")} >= api
    assert (ROOT / "app" / "detection" / "engine.py").is_file()
    assert (ROOT / "backend" / "routes").is_dir()
