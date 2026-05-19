#!/usr/bin/env python3
"""Real-time TUI dashboard for an FM-Agent run.

Usage:
    uv run python dashboard.py <proj_dir>                        # live: <proj_dir>/fm_agent/
    uv run python dashboard.py <proj_dir>/fm_agent.archived_xx   # any workspace dir (auto-detected by trace/ subdir)
    uv run python dashboard.py <proj_dir> --refresh 1.0          # refresh every 1.0s

Reads:
    <workdir>/trace/events.jsonl          (FM-Agent native events)
    <workdir>/trace/opencode/*.jsonl      (lucentia opencode-trace records)
    <workdir>/bug_validation/*.result.json (bug validation verdicts)

Standalone — run in a second terminal while main.py is going.
"""

import argparse
import glob
import json
import os
import sys
import time
from collections import deque, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import litellm
    _MODEL_COST = litellm.model_cost
except Exception:
    _MODEL_COST = {}

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress_bar import ProgressBar
from rich.align import Align


STAGES = ["init", "setup_context", "spec_generation", "verification", "bug_validation"]
CACHE_WINDOW = 200


def _parse_iso(ts):
    if not ts:
        return None
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _fmt_duration(seconds):
    if seconds is None:
        return "—"
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def _fmt_tokens(n):
    if n is None:
        return "—"
    if n >= 1_000_000:
        return f"{n/1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


def _fmt_cost(cents):
    if cents is None:
        return "—"
    return f"${cents:.4f}"


def _price_for(model):
    if not model:
        return None
    key = model
    if key in _MODEL_COST:
        return _MODEL_COST[key]
    # try stripping a "provider/" prefix
    if "/" in key:
        bare = key.split("/", 1)[1]
        if bare in _MODEL_COST:
            return _MODEL_COST[bare]
    return None


def _strip_star(d):
    """Strip leading '*' from dict keys (lucentia opencode-trace streaming convention)."""
    if not isinstance(d, dict):
        return d
    return {(k[1:] if k.startswith("*") else k): v for k, v in d.items()}


def _get_nested(d, *keys):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _cost_from_usage(model, usage):
    """Return USD cost for one anthropic-style usage dict, or 0 if unknown."""
    p = _price_for(model)
    if not p or not usage:
        return 0.0
    inp = usage.get("input_tokens", 0) or 0
    out = usage.get("output_tokens", 0) or 0
    cr = usage.get("cache_read_input_tokens", 0) or 0
    cw = usage.get("cache_creation_input_tokens", 0) or 0
    return (
        inp * (p.get("input_cost_per_token") or 0)
        + out * (p.get("output_cost_per_token") or 0)
        + cr * (p.get("cache_read_input_token_cost") or 0)
        + cw * (p.get("cache_creation_input_token_cost") or 0)
    )


def _locate_workdir(proj_dir):
    """Resolve which fm_agent workdir to monitor.

    Accepts either:
      - A project root: dashboard looks for <root>/fm_agent/ (the live workspace).
      - A workspace directly (any name like fm_agent.opus_partial_*): detected
        by the presence of a `trace/` subdir, used as-is.
    """
    p = Path(proj_dir).resolve()
    if (p / "trace").is_dir():
        return p
    return p / "fm_agent"


class State:
    """Aggregated trace state. Mutated by tail_* methods on each refresh."""

    def __init__(self, proj_dir):
        self.proj_dir = Path(proj_dir).resolve()
        self.workdir = _locate_workdir(self.proj_dir)
        self.trace_dir = self.workdir / "trace"
        self.events_path = self.trace_dir / "events.jsonl"
        self.opencode_dir = self.trace_dir / "opencode"
        self.bug_dir = self.workdir / "bug_validation"

        # Tail offsets
        self._events_offset = 0
        self._opencode_offsets = {}      # filename → byte offset

        # Aggregates
        self.first_event_time = None
        self.last_event_time = None
        self.stage_counts = defaultdict(lambda: defaultdict(int))   # stage → status → n
        self.stage_active = defaultdict(int)                        # stage → in-flight count (start-end pairs)
        self.totals = defaultdict(int)                              # token bucket → n
        self.cost_native = 0.0
        self.model_seen = None
        self.cache_window = deque(maxlen=CACHE_WINDOW)              # recent (cache_read, total_input) tuples
        self.recent_events = deque(maxlen=40)                       # (time, stage, status, summary)
        self.opencode_token_totals = defaultdict(int)               # stage → tokens
        self.opencode_cost = 0.0
        self.opencode_calls = 0

        # Verification verdicts
        self.verification_success = 0
        self.verification_mismatch = 0
        self.verification_error = 0

        # Bug validation
        self.bugs_confirmed = 0
        self.bugs_not_confirmed = 0
        self.bugs_pending = 0     # opencode call done but no result.json yet

    # ---------- events.jsonl tail ----------
    def tail_events(self):
        if not self.events_path.exists():
            return
        size = self.events_path.stat().st_size
        if size < self._events_offset:
            # file truncated/rotated
            self._events_offset = 0
        if size == self._events_offset:
            return
        with open(self.events_path, "r", encoding="utf-8") as f:
            f.seek(self._events_offset)
            for line in f:
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                self._ingest_event(ev)
            self._events_offset = f.tell()

    def _ingest_event(self, ev):
        et = ev.get("type")
        stage = ev.get("stage", "?")
        status = ev.get("status", "?")
        start = _parse_iso(ev.get("start_time"))
        end = _parse_iso(ev.get("end_time"))
        if start and (self.first_event_time is None or start < self.first_event_time):
            self.first_event_time = start
        if end and (self.last_event_time is None or end > self.last_event_time):
            self.last_event_time = end

        self.stage_counts[stage][status] += 1

        if et == "llm_call":
            md = ev.get("metadata", {})
            model = md.get("model")
            if model and not self.model_seen:
                self.model_seen = model
            usage = md.get("usage") or {}
            if usage:
                # Anthropic-native shape (from new llm_client)
                inp = usage.get("input_tokens", 0) or 0
                out = usage.get("output_tokens", 0) or 0
                cr = usage.get("cache_read_input_tokens", 0) or 0
                cw = usage.get("cache_creation_input_tokens", 0) or 0
                if not any([inp, out, cr, cw]):
                    # OpenAI shape (svip compat path or older runs)
                    inp = usage.get("prompt_tokens", 0) or 0
                    out = usage.get("completion_tokens", 0) or 0
                self.totals["input"] += inp
                self.totals["output"] += out
                self.totals["cache_read"] += cr
                self.totals["cache_write"] += cw
                self.cost_native += _cost_from_usage(model, usage)
                total_in = inp + cr + cw
                if total_in > 0:
                    self.cache_window.append((cr, total_in))

            if status == "success" and md.get("purpose") == "check_post_implies_spec":
                self.verification_success += 1
            elif status == "mismatch":
                self.verification_mismatch += 1
            elif status == "error":
                self.verification_error += 1

            summary = ev.get("summary") or md.get("purpose") or "llm_call"
            self._push_recent(end or start, stage, status, summary)

        elif et == "opencode_call":
            summary = ev.get("summary") or "opencode_call"
            self._push_recent(end or start, stage, status, summary)

    def _push_recent(self, ts, stage, status, summary):
        when = ts.strftime("%H:%M:%S") if ts else ""
        self.recent_events.appendleft((when, stage, status, summary))

    # ---------- opencode/*.jsonl tail ----------
    def tail_opencode(self):
        if not self.opencode_dir.exists():
            return
        for path in sorted(self.opencode_dir.glob("*.jsonl")):
            name = path.name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            off = self._opencode_offsets.get(name, 0)
            if size < off:
                off = 0
            if size == off:
                continue
            with open(path, "r", encoding="utf-8") as f:
                f.seek(off)
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    self._ingest_opencode(rec)
                self._opencode_offsets[name] = f.tell()

    def _ingest_opencode(self, rec):
        # opencode-trace alternates request and response; usage lives on responses.
        # The @lucentia plugin prefixes streaming-delta keys with "*" (e.g. "*usage",
        # "*input_tokens"). Older runs used plain names. Strip the prefix so both work.
        rec = _strip_star(rec)
        usage = rec.get("usage")
        if not isinstance(usage, dict):
            return
        usage = _strip_star(usage)
        inp = usage.get("input_tokens") or usage.get("prompt_tokens") or 0
        out = usage.get("output_tokens") or usage.get("completion_tokens") or 0
        if not (inp or out):
            return  # not a response payload
        self.opencode_calls += 1
        cr = (usage.get("cache_read_input_tokens")
              or _get_nested(usage, "prompt_tokens_details", "cached_tokens")
              or _get_nested(usage, "input_tokens_details", "cached_tokens")
              or 0)
        cw = (usage.get("cache_creation_input_tokens")
              or usage.get("claude_cache_creation_5_m_tokens")
              or 0)
        self.opencode_token_totals["input"] += inp
        self.opencode_token_totals["output"] += out
        self.opencode_token_totals["cache_read"] += cr
        self.opencode_token_totals["cache_write"] += cw
        model = rec.get("model")
        self.opencode_cost += _cost_from_usage(model, {
            "input_tokens": inp, "output_tokens": out,
            "cache_read_input_tokens": cr, "cache_creation_input_tokens": cw,
        })
        total_in = inp + cr + cw
        if total_in > 0:
            self.cache_window.append((cr, total_in))

    # ---------- bug_validation/*.result.json ----------
    def scan_bugs(self):
        self.bugs_confirmed = 0
        self.bugs_not_confirmed = 0
        if not self.bug_dir.exists():
            return
        for path in self.bug_dir.glob("*.result.json"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    d = json.load(f)
            except Exception:
                continue
            status = (d.get("confirmation_status") or "").lower()
            if "not" in status:
                self.bugs_not_confirmed += 1
            elif "confirm" in status:
                self.bugs_confirmed += 1
            else:
                self.bugs_not_confirmed += 1  # treat unknown as not confirmed
        # pending = bug_validation opencode_calls with success status, minus results files
        bv = self.stage_counts.get("bug_validation", {})
        bv_done = sum(bv.values())
        self.bugs_pending = max(0, bv_done - (self.bugs_confirmed + self.bugs_not_confirmed))

    # ---------- derived ----------
    def cache_hit_rate(self):
        if not self.cache_window:
            return None
        cr_total = sum(cr for cr, _ in self.cache_window)
        in_total = sum(t for _, t in self.cache_window)
        if in_total == 0:
            return None
        return cr_total / in_total

    def elapsed(self):
        if self.first_event_time is None:
            return None
        end = self.last_event_time or datetime.now(timezone.utc)
        return (end - self.first_event_time).total_seconds()


# ---------- rendering ----------

def render_header(state):
    parts = [
        f"[bold cyan]FM-Agent Dashboard[/]",
        f"[dim]workdir:[/] {state.workdir}",
        f"[dim]model:[/] {state.model_seen or '?'}",
        f"[dim]elapsed:[/] {_fmt_duration(state.elapsed())}",
    ]
    return Panel(Text.from_markup("  •  ".join(parts)), border_style="cyan")


def render_stages(state):
    table = Table(show_header=True, header_style="bold", expand=True, pad_edge=False)
    table.add_column("Stage", style="cyan", no_wrap=True)
    table.add_column("✓", justify="right", style="green")
    table.add_column("⚠ mismatch", justify="right", style="yellow")
    table.add_column("✗ error", justify="right", style="red")
    table.add_column("fmt", justify="right", style="magenta")
    for st in STAGES:
        counts = state.stage_counts.get(st, {})
        table.add_row(
            st,
            str(counts.get("success", 0)),
            str(counts.get("mismatch", 0)),
            str(counts.get("error", 0)),
            str(counts.get("format_error", 0)),
        )
    return Panel(table, title="Stages", border_style="cyan")


def render_tokens(state):
    p = _price_for(state.model_seen or "")
    table = Table(show_header=True, header_style="bold", expand=True, pad_edge=False)
    table.add_column("Source", style="cyan", no_wrap=True)
    table.add_column("input", justify="right")
    table.add_column("output", justify="right")
    table.add_column("c-read", justify="right", style="green")
    table.add_column("c-write", justify="right", style="yellow")
    table.add_column("cost", justify="right", style="bold")

    # native (verification LLM)
    table.add_row(
        "verification",
        _fmt_tokens(state.totals.get("input", 0)),
        _fmt_tokens(state.totals.get("output", 0)),
        _fmt_tokens(state.totals.get("cache_read", 0)),
        _fmt_tokens(state.totals.get("cache_write", 0)),
        _fmt_cost(state.cost_native),
    )
    # opencode-side
    table.add_row(
        f"opencode ({state.opencode_calls})",
        _fmt_tokens(state.opencode_token_totals.get("input", 0)),
        _fmt_tokens(state.opencode_token_totals.get("output", 0)),
        _fmt_tokens(state.opencode_token_totals.get("cache_read", 0)),
        _fmt_tokens(state.opencode_token_totals.get("cache_write", 0)),
        _fmt_cost(state.opencode_cost),
    )
    # total
    total_cost = state.cost_native + state.opencode_cost
    table.add_row(
        "[bold]TOTAL[/]",
        "",
        "",
        "",
        "",
        f"[bold]{_fmt_cost(total_cost)}[/]",
    )
    sub = ""
    if p:
        sub = (f" [dim]rates: in ${p.get('input_cost_per_token',0)*1e6:.2f}/M  "
               f"out ${p.get('output_cost_per_token',0)*1e6:.2f}/M  "
               f"cr ${p.get('cache_read_input_token_cost',0)*1e6:.2f}/M  "
               f"cw ${p.get('cache_creation_input_token_cost',0)*1e6:.2f}/M[/]")
    return Panel(table, title=f"Tokens & Cost{sub}", border_style="green")


def render_cache(state):
    def bar_line(label, cr, tot):
        if tot == 0:
            return f"[dim]{label:<14}(no data)[/]"
        rate = cr / tot
        pct = rate * 100
        bar_w = 20
        filled = int(bar_w * rate)
        bar = "█" * filled + "░" * (bar_w - filled)
        color = "green" if pct >= 80 else ("yellow" if pct >= 50 else "red")
        return f"{label:<14}[bold {color}]{pct:5.1f}%[/]  [{color}]{bar}[/]"

    n_cr = state.totals.get("cache_read", 0)
    n_in = state.totals.get("input", 0) + state.totals.get("cache_write", 0)
    o_cr = state.opencode_token_totals.get("cache_read", 0)
    o_in = (state.opencode_token_totals.get("input", 0)
            + state.opencode_token_totals.get("cache_write", 0))

    lines = [
        bar_line("verification", n_cr, n_cr + n_in),
        bar_line("opencode",     o_cr, o_cr + o_in),
        "",
    ]

    wnd_cr = sum(cr for cr, _ in state.cache_window)
    wnd_tot = sum(t for _, t in state.cache_window)
    if wnd_tot > 0:
        lines.append(
            f"[dim]recent {len(state.cache_window)}/{CACHE_WINDOW} calls: "
            f"{_fmt_tokens(wnd_cr)} / {_fmt_tokens(wnd_tot)} input[/]"
        )

    # cost-savings estimate: cache_read tokens would otherwise have been
    # billed as fresh input (cache_write is its own cost, already in TOTAL).
    p = _price_for(state.model_seen or "")
    if p:
        in_per = p.get("input_cost_per_token") or 0
        cr_per = p.get("cache_read_input_token_cost") or 0
        total_cr = n_cr + o_cr
        if in_per > 0 and total_cr > 0:
            saved = total_cr * (in_per - cr_per)
            actual = state.cost_native + state.opencode_cost
            if saved > 0:
                pct = saved / (actual + saved) * 100 if actual + saved > 0 else 0
                lines.append(
                    f"[bold green]saved ~${saved:.2f} by cache[/]"
                    f"  [dim]({pct:.0f}% off no-cache)[/]"
                )

    if n_cr + n_in == 0 and o_cr + o_in == 0:
        text = Text.from_markup("[dim](no token data yet)[/]")
    else:
        text = Text.from_markup("\n".join(lines))
    return Panel(Align.center(text, vertical="middle"),
                 title="Cache Hit Rate", border_style="green")


def render_bugs(state):
    total = state.bugs_confirmed + state.bugs_not_confirmed + state.bugs_pending
    text = Text.from_markup(
        f"[green]✓ confirmed[/]      {state.bugs_confirmed}\n"
        f"[yellow]✗ not_confirmed[/]  {state.bugs_not_confirmed}\n"
        f"[dim]… pending[/]         {state.bugs_pending}\n"
        f"[bold]total[/]             [bold]{total}[/]"
    )
    return Panel(Align.center(text, vertical="middle"),
                 title="Bug Validation", border_style="yellow")


def render_recent(state):
    table = Table(show_header=True, header_style="bold", expand=True, pad_edge=False)
    table.add_column("time", style="dim", no_wrap=True)
    table.add_column("stage", style="cyan", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("summary", overflow="ellipsis", no_wrap=True)
    for when, stage, status, summary in list(state.recent_events):
        color = {
            "success": "green",
            "mismatch": "yellow",
            "error": "red",
            "format_error": "magenta",
        }.get(status, "white")
        table.add_row(when, stage, f"[{color}]{status}[/]", summary)
    return Panel(table, title="Recent Events", border_style="cyan")


def build_layout(state):
    # Heights are computed to exactly fit content. A Rich Table renders as
    #   2 (top+bottom edge) + 1 (header) + 1 (header-rule) + N (rows)
    # and Panel adds 2 more border lines, so a Table-in-Panel = N + 6 lines.
    # A Text-in-Panel = N_lines + 2. Small panels (cache, bugs) are Align-centered
    # so the spare height goes evenly above/below instead of bunching at the top.
    stages_h = len(STAGES) + 6                 # 5 + 6 = 11
    tokens_h = 3 + 6                           # 3 rows ("verification", "opencode", "TOTAL") + 6 = 9

    layout = Layout()
    layout.split_column(
        Layout(render_header(state), name="header", size=3),
        Layout(name="top", size=stages_h),
        Layout(name="mid", size=tokens_h),
        Layout(render_recent(state), name="footer"),
    )
    layout["top"].split_row(
        Layout(render_stages(state), name="stages", ratio=3),
        Layout(render_cache(state), name="cache", ratio=2),
    )
    layout["mid"].split_row(
        Layout(render_tokens(state), name="tokens", ratio=3),
        Layout(render_bugs(state), name="bugs", ratio=1),
    )
    return layout


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("proj_dir",
                    help=("Either a target codebase (monitors <proj_dir>/fm_agent/) "
                          "or a workspace directly (any dir containing a trace/ subdir)"))
    ap.add_argument("--refresh", type=float, default=1.5, help="Refresh seconds (default 1.5)")
    args = ap.parse_args()

    state = State(args.proj_dir)
    if not state.trace_dir.exists():
        print(f"trace dir not found: {state.trace_dir}", file=sys.stderr)
        print("Has the pipeline started yet? (waiting…)", file=sys.stderr)

    console = Console()
    with Live(console=console, refresh_per_second=max(1.0, 1.0 / args.refresh),
              screen=True) as live:
        try:
            while True:
                state.tail_events()
                state.tail_opencode()
                state.scan_bugs()
                live.update(build_layout(state))
                time.sleep(args.refresh)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
