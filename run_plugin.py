"""Generic CLI to run an analysis plugin over a project directory.

Usage:
    python3 run_plugin.py <plugin> <proj_dir>
    python3 run_plugin.py --openai --model gpt-5.5 <plugin> <proj_dir>
    python3 run_plugin.py --deepseek --model deepseek-v4-pro <plugin> <proj_dir>

where <plugin> is one of the registered plugin names (see src/plugins/registry).

This is the unified entry point that replaces per-track drivers like
ifc_main.py: every plugin runs through the same src/plugins/driver.run_plugin.
Plugin discovery + class loading go through src.plugins.registry, so adding a
plugin needs no edit here.
"""

import argparse
import ast
import concurrent.futures
import os
import subprocess
import sys
import logging

from dotenv import load_dotenv

from src.plugins import registry


load_dotenv()


def _parse_args(argv):
    names = ", ".join(registry.plugin_names())
    parser = argparse.ArgumentParser(
        description="Run one FM-Agent security plugin over a project directory.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("plugin", nargs="?", help=f"plugin name ({names}, or all)")
    parser.add_argument("proj_dir", nargs="?", help="project directory to analyze")
    parser.add_argument(
        "--config",
        help=(
            "Codex-style TOML config to map model, provider base_url, wire_api, "
            "reasoning effort, and response-storage settings."
        ),
    )
    parser.add_argument(
        "--model",
        help="LLM model id. Sets LLM_MODEL before the LLM client is imported.",
    )
    parser.add_argument(
        "--base-url",
        help="OpenAI-compatible API base URL. Sets LLM_API_BASE_URL.",
    )
    parser.add_argument(
        "--api-key-env",
        default="LLM_API_KEY",
        help="environment variable that contains the API key.",
    )
    parser.add_argument(
        "--api-mode",
        choices=("chat", "responses"),
        help="OpenAI-compatible API surface used for non-Anthropic models.",
    )
    parser.add_argument(
        "--reasoning-effort",
        help="Responses API reasoning effort. Sets LLM_EFFORT.",
    )
    parser.add_argument(
        "--disable-response-storage",
        action="store_true",
        help="pass store=false on Responses API calls.",
    )
    parser.add_argument(
        "--openai",
        action="store_true",
        help=(
            "use the OpenAI API base URL, default to Responses API, and read "
            "OPENAI_API_KEY if LLM_API_KEY is unset."
        ),
    )
    parser.add_argument(
        "--deepseek",
        action="store_true",
        help=(
            "use the DeepSeek OpenAI-compatible Chat Completions API, default "
            "to deepseek-v4-pro, and read DEEPSEEK_API_KEY if LLM_API_KEY is unset."
        ),
    )
    parser.add_argument(
        "--plugin-workers",
        type=int,
        help=(
            "maximum number of plugins to run concurrently when plugin=all. "
            "Defaults to FM_AGENT_PLUGIN_WORKERS or all registered plugins."
        ),
    )
    args = parser.parse_args(argv)
    if not args.plugin or not args.proj_dir:
        parser.print_usage()
        print(f"Available plugins: {names}")
        raise SystemExit(1)
    return args


def _parse_config_value(raw):
    raw = raw.split("#", 1)[0].strip()
    if not raw:
        return ""
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if raw[0] in {"'", '"'}:
        try:
            return ast.literal_eval(raw)
        except (SyntaxError, ValueError):
            return raw.strip("'\"")
    return raw


def _load_codex_style_config(path):
    """Extract the Codex provider fields run_plugin.py needs.

    This intentionally small parser keeps Python 3.10 compatibility and ignores
    unrelated or malformed lines, including pasted env JSON blocks.
    """
    data = {}
    section = ()
    with open(path) as fp:
        for line in fp:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = tuple(part.strip() for part in stripped[1:-1].split("."))
                continue
            if "=" not in stripped:
                continue
            key, raw_value = stripped.split("=", 1)
            key = key.strip()
            value = _parse_config_value(raw_value)
            cursor = data
            for part in section:
                cursor = cursor.setdefault(part, {})
            cursor[key] = value
    return data


def _apply_config_env(path):
    cfg = _load_codex_style_config(path)
    if cfg.get("model"):
        os.environ.setdefault("LLM_MODEL", str(cfg["model"]))
    if cfg.get("model_reasoning_effort"):
        os.environ.setdefault("LLM_EFFORT", str(cfg["model_reasoning_effort"]))
    if cfg.get("disable_response_storage") is True:
        os.environ.setdefault("LLM_DISABLE_RESPONSE_STORAGE", "true")

    provider_name = cfg.get("model_provider") or "OpenAI"
    provider = (cfg.get("model_providers") or {}).get(str(provider_name), {})
    if provider.get("base_url"):
        os.environ.setdefault("LLM_API_BASE_URL", str(provider["base_url"]))
    if provider.get("wire_api"):
        os.environ.setdefault("LLM_API_MODE", str(provider["wire_api"]).lower())
    if provider.get("requires_openai_auth") is True and not os.environ.get("LLM_API_KEY"):
        if os.environ.get("OPENAI_API_KEY"):
            os.environ["LLM_API_KEY"] = os.environ["OPENAI_API_KEY"]


def _configure_llm_env(args):
    if args.config:
        _apply_config_env(args.config)

    if args.deepseek:
        os.environ.setdefault("LLM_API_BASE_URL", "https://api.deepseek.com")
        os.environ.setdefault("LLM_API_MODE", "chat")
        os.environ.setdefault("LLM_MODEL", "deepseek-v4-pro")
        if not os.environ.get("LLM_API_KEY") and os.environ.get("DEEPSEEK_API_KEY"):
            os.environ["LLM_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]

    if args.openai:
        os.environ.setdefault("LLM_API_BASE_URL", "https://api.openai.com/v1")
        os.environ.setdefault("LLM_API_MODE", "responses")
        if not os.environ.get("LLM_API_KEY") and os.environ.get("OPENAI_API_KEY"):
            os.environ["LLM_API_KEY"] = os.environ["OPENAI_API_KEY"]
    if args.base_url:
        os.environ["LLM_API_BASE_URL"] = args.base_url
    if args.model:
        os.environ["LLM_MODEL"] = args.model
    if args.api_mode:
        os.environ["LLM_API_MODE"] = args.api_mode
    if args.reasoning_effort:
        os.environ["LLM_EFFORT"] = args.reasoning_effort
    if args.disable_response_storage:
        os.environ["LLM_DISABLE_RESPONSE_STORAGE"] = "true"

    key = os.environ.get(args.api_key_env)
    if args.api_key_env != "LLM_API_KEY" and key:
        os.environ["LLM_API_KEY"] = key

    requires_llm = True
    if registry.has_plugin(args.plugin):
        requires_llm = registry.get_manifest(args.plugin).get("requires_llm", True) is not False

    if requires_llm and not os.environ.get("LLM_API_KEY"):
        raise SystemExit(
            "LLM_API_KEY is not set. Export LLM_API_KEY, or use "
            "--openai with OPENAI_API_KEY, or pass --api-key-env NAME."
        )


def _plugin_worker_count(args, plugin_count):
    configured = args.plugin_workers
    if configured is None and os.environ.get("FM_AGENT_PLUGIN_WORKERS"):
        try:
            configured = int(os.environ["FM_AGENT_PLUGIN_WORKERS"])
        except ValueError:
            configured = None
    if configured is None:
        configured = plugin_count
    return max(1, min(plugin_count, configured))


def _command_for_plugin(args, plugin_name):
    cmd = [sys.executable, os.path.abspath(__file__)]
    if args.config:
        cmd.extend(["--config", args.config])
    if args.model:
        cmd.extend(["--model", args.model])
    if args.base_url:
        cmd.extend(["--base-url", args.base_url])
    if args.api_key_env:
        cmd.extend(["--api-key-env", args.api_key_env])
    if args.api_mode:
        cmd.extend(["--api-mode", args.api_mode])
    if args.reasoning_effort:
        cmd.extend(["--reasoning-effort", args.reasoning_effort])
    if args.disable_response_storage:
        cmd.append("--disable-response-storage")
    if args.openai:
        cmd.append("--openai")
    if args.deepseek:
        cmd.append("--deepseek")
    cmd.extend([plugin_name, args.proj_dir])
    return cmd


def _run_plugin_subprocess(args, plugin_name):
    cmd = _command_for_plugin(args, plugin_name)
    return plugin_name, subprocess.run(
        cmd,
        cwd=os.getcwd(),
        env=os.environ.copy(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def _run_all_plugins_parallel(args, plugin_names):
    workers = _plugin_worker_count(args, len(plugin_names))
    print(f"[all] Running {len(plugin_names)} plugins with {workers} worker(s): "
          f"{', '.join(plugin_names)}")
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_run_plugin_subprocess, args, name): name
            for name in plugin_names
        }
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                plugin_name, completed = future.result()
            except Exception as exc:  # noqa: BLE001 - isolate plugin launch failures
                print(f"\n===== [{name}] FAILED TO LAUNCH =====")
                print(exc)
                failures.append(name)
                continue
            print(f"\n===== [{plugin_name}] output =====")
            if completed.stdout:
                print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
            if completed.returncode != 0:
                print(f"===== [{plugin_name}] FAILED rc={completed.returncode} =====")
                failures.append(plugin_name)
            else:
                print(f"===== [{plugin_name}] OK =====")
    if failures:
        print(f"[all] Failed plugins: {', '.join(sorted(failures))}")
        return 1
    print("[all] All plugins completed successfully.")
    return 0


def main():
    args = _parse_args(sys.argv[1:])
    _configure_llm_env(args)

    plugin_name, proj_dir = args.plugin, args.proj_dir
    if plugin_name == "all":
        plugin_names = registry.plugin_names()
    elif registry.has_plugin(plugin_name):
        plugin_names = [plugin_name]
    else:
        print(f"Unknown plugin '{plugin_name}'. Available: {', '.join(registry.plugin_names())}, all")
        return 1

    logging.basicConfig(level=logging.WARNING)
    if plugin_name == "all":
        return _run_all_plugins_parallel(args, plugin_names)

    from src.plugins.driver import run_plugin

    for name in plugin_names:
        plugin_cls = registry.load_plugin_class(name)
        work_subdir = registry.get_manifest(name).get("work_subdir")
        run_plugin(plugin_cls(), proj_dir, work_subdir=work_subdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
