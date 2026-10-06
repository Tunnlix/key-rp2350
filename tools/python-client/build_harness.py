"""Compile the host peer; build orchestration stays outside the report adapter.

Run from the project: .venv/Scripts/python.exe tools/python-client/build_harness.py
Compiler lookup: explicit CC, PATH, then the project's Windows build task.
Windows WinGet WinLibs installations are also detected without changing PATH.
"""

from __future__ import annotations

import os
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def find_compiler() -> Path:
    """Reuse project compiler configuration when a terminal lacks GCC on PATH."""
    override = os.environ.get("CC")
    if override:
        found = shutil.which(override)
        if found:
            return Path(found).resolve()
        raise RuntimeError(f"CC does not name an available compiler executable: {override}")
    found = shutil.which("gcc")
    if found:
        return Path(found).resolve()
    if os.name == "nt":
        task_file = ROOT / ".vscode/tasks.json"
        if task_file.is_file():
            tasks = json.loads(task_file.read_text(encoding="utf-8-sig"))
            for task in tasks.get("tasks", []):
                if task.get("label") != "Build C program":
                    continue
                command = task.get("windows", {}).get("command", task.get("command", ""))
                command = command.replace("${workspaceFolder}", str(ROOT))
                command = re.sub(r"\$\{env:([^}]+)\}",
                                 lambda match: os.environ.get(match[1], ""), command)
                found = shutil.which(command)
                if found:
                    return Path(found).resolve()
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            packages = Path(local_app_data) / "Microsoft/WinGet/Packages"
            for candidate in sorted(packages.glob("BrechtSanders.WinLibs*/mingw64/bin/gcc.exe")):
                if candidate.is_file():
                    return candidate.resolve()
    raise RuntimeError("GCC was not found on PATH or in the project configuration; set CC to its executable path")


def build_harness() -> Path:
    compiler = find_compiler()
    output = ROOT / "build" / ("ctaphid_harness.exe" if os.name == "nt" else "ctaphid_harness")
    output.parent.mkdir(exist_ok=True)
    sources = [ROOT / "examples/host/main.c", ROOT / "examples/host/stdio_transport.c",
               ROOT / "examples/host/host_actions.c", ROOT / "examples/host/host_clock.c",
               ROOT / "examples/host/host_presence.c", ROOT / "examples/host/host_storage.c"]
    sources.extend(sorted((ROOT / "src/protocol").glob("*.c")))
    sources.extend(sorted((ROOT / "src/ctap").glob("*.c")))
    # GCC's helper tools/DLLs may also live in bin. Only the compiler subprocess
    # receives this PATH addition; the user's terminal configuration is untouched.
    compiler_env = dict(os.environ)
    compiler_env["PATH"] = str(compiler.parent) + os.pathsep + compiler_env.get("PATH", "")
    subprocess.run(
        [str(compiler), "-std=c17", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
         "-I", str(ROOT / "include"), *map(str, sources),
         *(["-lbcrypt"] if os.name == "nt" else []), "-o", str(output)],
        cwd=ROOT, env=compiler_env, check=True,
    )
    return output


if __name__ == "__main__":
    print(build_harness())
