from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} 必须是整数，当前值为 {raw!r}") from exc
    if value <= 0:
        raise SystemExit(f"{name} 必须大于 0，当前值为 {value}")
    return value


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_root: Path
    data_dir: Path
    host: str
    port: int
    max_concurrent_tasks: int
    max_project_files: int
    max_project_bytes: int
    max_material_files: int
    max_material_bytes: int
    max_requirement_files: int
    max_requirement_bytes: int
    max_request_bytes: int
    scan_interval_s: float
    enrich_workers: int
    enrich_timeout_s: int
    enrich_base_url: str
    enrich_api_key: str
    enrich_model: str
    tool_compat_mode: str
    demo_mode: bool

    @classmethod
    def from_env(cls) -> "Settings":
        app_root = Path(__file__).resolve().parent.parent
        agent_base_url = os.environ.get("LLM_API_BASE_URL") or "https://api.deepseek.com"
        agent_api_key = os.environ.get("LLM_API_KEY") or ""
        agent_model = os.environ.get("LLM_MODEL") or "deepseek-flash"
        agent_tool_mode = os.environ.get("FM_AGENT_TOOL_COMPAT_MODE") or "native"
        try:
            # The bundled runtime has the original tool's dependencies. Reading
            # its validated settings keeps Web enrichment on exactly the same
            # route even when values came from fm-agent.toml/secrets.env rather
            # than process environment variables.
            from config import settings as agent_settings

            agent_base_url = agent_settings.llm.base_url
            agent_api_key = agent_settings.llm.api_key
            agent_model = agent_settings.llm.name
            agent_tool_mode = agent_settings.llm.tool_compat_mode
        except ModuleNotFoundError:
            # A dependency-light developer/test interpreter may not be able to
            # import the original configuration stack; environment fallback is
            # sufficient there. Production always runs the bundled interpreter.
            pass
        data_dir = Path(
            os.environ.get("FM_WEB_DATA_DIR", str(app_root / "webapp_data"))
        ).expanduser().resolve()
        max_project_bytes = _positive_int("FM_WEB_MAX_PROJECT_MB", 10) * 1024 * 1024
        max_material_bytes = _positive_int("FM_WEB_MAX_MATERIAL_MB", 5) * 1024 * 1024
        max_requirement_bytes = _positive_int("FM_WEB_MAX_REQUIREMENT_MB", 20) * 1024 * 1024
        return cls(
            app_root=app_root,
            data_dir=data_dir,
            host=os.environ.get("FM_WEB_HOST", "0.0.0.0"),
            port=_positive_int("FM_WEB_PORT", 8080),
            max_concurrent_tasks=_positive_int("FM_WEB_MAX_CONCURRENT_TASKS", 5),
            max_project_files=_positive_int("FM_WEB_MAX_PROJECT_FILES", 200),
            max_project_bytes=max_project_bytes,
            max_material_files=_positive_int("FM_WEB_MAX_MATERIAL_FILES", 20),
            max_material_bytes=max_material_bytes,
            max_requirement_files=_positive_int("FM_WEB_MAX_REQUIREMENT_FILES", 10),
            max_requirement_bytes=max_requirement_bytes,
            max_request_bytes=(
                max_project_bytes
                + max_material_bytes * 2
                + max_requirement_bytes
                + 2 * 1024 * 1024
            ),
            scan_interval_s=max(
                0.2, float(os.environ.get("FM_WEB_SCAN_INTERVAL_SECONDS", "0.75"))
            ),
            enrich_workers=_positive_int("FM_WEB_ENRICH_WORKERS", 2),
            enrich_timeout_s=_positive_int("FM_WEB_ENRICH_TIMEOUT_SECONDS", 120),
            enrich_base_url=agent_base_url.rstrip("/"),
            enrich_api_key=agent_api_key,
            enrich_model=agent_model,
            tool_compat_mode=agent_tool_mode,
            demo_mode=_flag("FM_WEB_DEMO_MODE"),
        )

    @property
    def tasks_dir(self) -> Path:
        return self.data_dir / "tasks"

    @property
    def database_path(self) -> Path:
        return self.data_dir / "fm-agent-web.sqlite3"

    @property
    def static_dir(self) -> Path:
        return Path(__file__).resolve().parent / "static"
