"""Lifecycle of one private bug-validator filesystem workspace."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import uuid
import json
from dataclasses import dataclass
from pathlib import Path


RUNTIME_ROOT_ENV = "FM_VALIDATOR_RUNTIME_ROOT"
SHORT_TMP_ROOT_ENV = "FM_VALIDATOR_SHORT_TMP_ROOT"

# PIN: validator-host-and-project-secrets-are-hidden
_TOP_LEVEL_EXCLUDES = (
    ".git",
    ".env",
    ".env.*",
    ".fm-validator-runtime",
    ".omo",
    "fm_agent",
    "target",
)


class ValidationWorkspaceError(RuntimeError):
    pass


def _safe_component(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")
    return safe[:120] or "validator"


def _runtime_base(project: Path) -> Path:
    configured = os.environ.get(RUNTIME_ROOT_ENV)
    if configured:
        return (
            Path(configured).expanduser().resolve()
            / _safe_component(project.name)
        )
    return (project / ".fm-validator-runtime").resolve()


def _short_tmp_root(project: Path) -> Path:
    configured = os.environ.get(SHORT_TMP_ROOT_ENV)
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(tempfile.gettempdir()).resolve() / ".fm-validator-tmp"


def _run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()[-800:]
        suffix = f": {detail}" if detail else ""
        raise ValidationWorkspaceError(
            f"workspace command failed: {' '.join(argv)}{suffix}"
        ) from exc


def copy_validation_source(source: Path, destination: Path) -> None:
    """Copy only source inputs needed by a validator or clean L1 build."""
    argv = ["rsync", "-a", "--delete"]
    for name in _TOP_LEVEL_EXCLUDES:
        argv.append(f"--exclude=/{name}")
    argv.extend((f"{source}/", f"{destination}/"))
    _run(argv)


@dataclass
class ValidationAttemptWorkspace:
    original_project: Path
    result_json_rel: Path
    bug_id: str
    attempt: int
    root: Path
    project_dir: Path
    validation_dir: Path
    scratch_parent: Path
    opencode_runtime: Path
    trace_dir: Path
    short_tmp_dir: Path
    extracted_function_rel: Path | None

    @classmethod
    def create(
        cls,
        original_project: Path | str,
        result_json_rel: Path | str,
        bug_id: str,
        attempt: int,
    ) -> "ValidationAttemptWorkspace":
        original = Path(original_project).resolve()
        relative_result = Path(result_json_rel)
        if relative_result.is_absolute() or ".." in relative_result.parts:
            raise ValidationWorkspaceError("logic result path must be project-relative")
        source_result = (original / relative_result).resolve()
        try:
            source_result.relative_to(original)
        except ValueError as exc:
            raise ValidationWorkspaceError("logic result path escapes the project") from exc
        if source_result.is_symlink() or not source_result.is_file():
            raise ValidationWorkspaceError(f"logic result is missing or unsafe: {source_result}")
        if type(attempt) is not int or attempt < 1:
            raise ValidationWorkspaceError("attempt must be a positive integer")

        base = _runtime_base(original)
        attempt_id = (
            f"{_safe_component(bug_id)}-attempt-{attempt}-{uuid.uuid4().hex}"
        )
        root = base / attempt_id
        project = root / "project"
        root.mkdir(parents=True, mode=0o700)
        try:
            project.mkdir()
            copy_validation_source(original, project)

            private_result = project / relative_result
            private_result.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_result, private_result)
            extracted_rel = None
            try:
                function_value = json.loads(source_result.read_text()).get("function")
                function_path = Path(function_value).resolve() \
                    if isinstance(function_value, str) else None
                if function_path is not None:
                    candidate_rel = function_path.relative_to(original)
                    if not function_path.is_symlink() and function_path.is_file() \
                            and candidate_rel.parts[:2] == ("fm_agent", "extracted_functions"):
                        extracted_rel = candidate_rel
                        destination = project / candidate_rel
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(function_path, destination)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                extracted_rel = None
            validation = project / "fm_agent" / "bug_validation"
            validation.mkdir(parents=True, exist_ok=True)
            scratch_parent = root / "scratch"
            opencode_runtime = root / "opencode-runtime"
            trace = root / "trace"
            short_tmp = _short_tmp_root(original) / uuid.uuid4().hex[:16]
            for directory in (scratch_parent, opencode_runtime, trace):
                directory.mkdir(mode=0o700)
            short_tmp.mkdir(parents=True, mode=0o700)
            return cls(
                original_project=original,
                result_json_rel=relative_result,
                bug_id=bug_id,
                attempt=attempt,
                root=root,
                project_dir=project,
                validation_dir=validation,
                scratch_parent=scratch_parent,
                opencode_runtime=opencode_runtime,
                trace_dir=trace,
                short_tmp_dir=short_tmp,
                extracted_function_rel=extracted_rel,
            )
        except Exception:
            shutil.rmtree(root, ignore_errors=True)
            if "short_tmp" in locals():
                shutil.rmtree(short_tmp, ignore_errors=True)
            raise

    @property
    def private_logic_result(self) -> Path:
        return self.project_dir / self.result_json_rel

    def opencode_environment(self) -> dict[str, str]:
        home = self.opencode_runtime / "home"
        data = self.opencode_runtime / "data"
        state = self.opencode_runtime / "state"
        cache = self.opencode_runtime / "cache"
        for directory in (home, data, state, cache, self.short_tmp_dir):
            directory.mkdir(parents=True, exist_ok=True)
        return {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(self.opencode_runtime / "config"),
            "XDG_DATA_HOME": str(data),
            "XDG_STATE_HOME": str(state),
            "XDG_CACHE_HOME": str(cache),
            "TMPDIR": str(self.short_tmp_dir),
            "CLAUDE_CODE_TMPDIR": str(self.short_tmp_dir),
            "OPENCODE_DB": str(data / "opencode.db"),
        }

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.short_tmp_dir, ignore_errors=True)
        try:
            self.short_tmp_dir.parent.rmdir()
        except OSError:
            pass
        try:
            self.root.parent.rmdir()
        except OSError:
            pass

    def __enter__(self) -> "ValidationAttemptWorkspace":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.cleanup()


# PIN: validator-attempts-use-private-writable-workspaces
def create_validation_workspace(
    original_project: Path | str,
    result_json_rel: Path | str,
    bug_id: str,
    attempt: int,
) -> ValidationAttemptWorkspace:
    return ValidationAttemptWorkspace.create(
        original_project, result_json_rel, bug_id, attempt,
    )
