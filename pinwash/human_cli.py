"""Human-facing commands, separate from the frozen `check` JSON interface."""
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

from pinwash.consumer import ConsumerError, collect, identity, inspect, record_error, summarize
from pinwash.report import render, safe
from pinwash.session import review, start
from pinwash.textutil import dump_json


def _text(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf-8"))


def _seconds(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or not 0 < number <= 3600:
        raise argparse.ArgumentTypeError("timeout must be greater than 0 and at most 3600 seconds")
    return number


def main(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="pinwash")
    commands = parser.add_subparsers(dest="command", required=True)
    one = commands.add_parser("review", help="Explain one diff; default is HEAD versus worktree")
    one.add_argument("range", nargs="?")
    session = commands.add_parser("session", help="Start and review an entire agent session")
    actions = session.add_subparsers(dest="action", required=True)
    begin = actions.add_parser("start", help="Record a clean starting commit outside the repository")
    begin.add_argument("--replace", action="store_true", help="Explicitly accept current HEAD as a new baseline; retain previous records")
    end = actions.add_parser("review", help="Review all committed and uncommitted session changes")
    end.add_argument("--stopped", action="store_true", help="Attest that the agent and all its writers have stopped (not verified by PinWash)")
    for command in (one, begin, end):
        command.add_argument("--json", action="store_true", help="Emit the consumer report including original engine results")
        command.add_argument("--timeout", type=_seconds, default=60, help="Seconds allowed per inspection/comparison (default: 60)")
    for command in (begin, end):
        command.add_argument("--state-dir", help="Trusted consumer state directory outside the subject repository")
    options = parser.parse_args(args)
    report = None
    try:
        repo = Path.cwd()
        if options.command == "review":
            before = inspect(repo, options.timeout)
            judge = identity()
            root = Path(before["repo"])
            report = summarize(collect(root, [options.range], options.timeout))
            report.update(judge=judge, repo=str(root), scope="single_diff")
            after = inspect(root, options.timeout)
            if before != after or judge != identity():
                record_error(report, "Repository or judge changed during review.")
        elif options.action == "start":
            state = start(repo, state_dir=options.state_dir, replace=options.replace, timeout=options.timeout)
            if options.json:
                sys.stdout.buffer.write(dump_json(state))
            else:
                _text(f"Session started at {state['base']}\nRepository: {safe(state['repo'])}\n"
                      f"State: {safe(state['state_path'])}\n"
                      "After the agent and all its writers stop, run: pinwash session review\n"
                      "Keep this installation and state outside the agent's writable scope.\n"
                      "Local state alone does not protect against same-user tampering.\n")
                if options.state_dir:
                    _text(f"Use the same --state-dir for review: {safe(str(Path(options.state_dir).expanduser().resolve()))}\n")
            return 0
        else:
            stopped = options.stopped
            if not stopped and sys.stdin.isatty():
                sys.stderr.write("Have the agent and ALL processes it started stopped writing? [y/N] ")
                sys.stderr.flush()
                try:
                    answer = input()
                except EOFError:
                    answer = ""
                stopped = answer.strip().lower() in ("y", "yes")
            report = review(repo, stopped=stopped, state_dir=options.state_dir, timeout=options.timeout)
        if options.json:
            sys.stdout.buffer.write(dump_json(report))
        else:
            _text(render(report))
        return report["exit_code"]
    except (ConsumerError, OSError) as exc:
        if report is None:
            report = summarize([])
        record_error(report, str(exc))
        if options.json:
            sys.stdout.buffer.write(dump_json(report))
        else:
            _text(render(report))
        return 2
