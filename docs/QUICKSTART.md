# Five-minute quickstart

PinWash helps you review changes that weaken an AI agent's verification setup:
removed hooks, relaxed checks, broader permissions and related supported files.
It reads the diff; it does not run your application's tests.

This is a **source candidate**, with no release or PyPI publication. The steps
below use a fixed source revision and a separate Python environment. The
five-minute target assumes Python 3.11+, Git, a POSIX shell and download access
are already available; download time varies. Linux is the current package
validation target. See the [candidate validation record](GUIDANCE_ACCEPTANCE.md)
before treating this revision as accepted; Windows/macOS acceptance is separate.

## 1. Install outside the project

Run this from a trusted terminal. These new directories keep the judge away
from the project your agent edits. If a directory already exists, choose a new
name rather than overwriting an existing installation or session.

```sh
test ! -e "$HOME/.local/share/pinwash-quickstart-env" &&
mkdir -p "$HOME/.local/share" &&
git clone https://github.com/taipei49314/pinwash.git "$HOME/.local/share/pinwash-quickstart-source" &&
git -C "$HOME/.local/share/pinwash-quickstart-source" checkout --detach 84a643b8352f0319628de6b8e6e19a47d4ff0e1e &&
python3 -m venv "$HOME/.local/share/pinwash-quickstart-env" &&
"$HOME/.local/share/pinwash-quickstart-env/bin/python" -m pip install "$HOME/.local/share/pinwash-quickstart-source" &&
. "$HOME/.local/share/pinwash-quickstart-env/bin/activate"
```

Stop if any command fails. Check `python3 --version` first if you are unsure
which Python is installed. Source installation downloads pinned setuptools
83.0.0; installed scans have no runtime dependencies or network requests.
An already accepted wheel can be installed instead; see [installation](INSTALL.md).
Keep this installation fixed until your session is reviewed.

## 2. Try a small, disposable example

This creates a new demo repository. The dummy hook is data for PinWash to read;
PinWash will not run it. No coding agent is needed for the example.

```sh
DEMO=$(mktemp -d) &&
cd "$DEMO" &&
git init -q &&
mkdir -p .claude hooks &&
printf '%s\n' '{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"python hooks/judge.py"}]}]}}' > .claude/settings.json &&
printf '%s\n' '# Demo verification hook' 'raise SystemExit("block")' > hooks/judge.py &&
git add . &&
git -c user.name="PinWash demo" -c user.email="demo@example.invalid" -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm "demo baseline" &&
pinwash session start &&
pinwash session status
```

Status should show an active session, the original baseline, a matching judge
and no saved review. It explicitly says **Current changes: NOT REVIEWED**.
If start failed, address its error before continuing.

Now simulate an agent removing the hook, then review:

```sh
cd "$DEMO" &&
printf '%s\n' '{"hooks":{}}' > .claude/settings.json &&
pinwash session review --stopped
```

`--stopped` is appropriate here because you control this demo and no agent or
other writer was started. Expect **exit 1** and a `HOOK_REMOVED` finding, with a
priority summary explaining what to review. Exit 1 is the expected detection
in this example, not an installation failure. The full report shows before,
after, reason and next action, followed by the saved JSON path.

Restore the demo hook and repeat the review against the same baseline:

```sh
cd "$DEMO" &&
git restore -- .claude/settings.json &&
pinwash session review --stopped &&
pinwash session status
```

The demo should now have no blocking in-scope changes (exit 0). Status shows
that saved result as **historical**; it never checks subsequent changes itself.
The demo and its local records remain available for inspection.

## 3. Use the two steps in your project

1. In your project's clean worktree, before the agent edits, run
   `pinwash session start`. Commit or stash existing edits yourself if needed.
2. After the agent **and every process it started** have stopped writing, run
   `pinwash session review` and answer the confirmation question. Read the
   priority summary, address the items, and repeat review with the same baseline.

Use `pinwash session status` whenever you need to see which baseline is active.
If you chose `--state-dir PATH`, use that same directory for all three commands.
After consciously accepting the completed work and committing it, use
`pinwash session start --replace` for the **next** session. Replacing a baseline
does not fix a failed review or approve an exemption.

| What you see | What to do next |
|---|---|
| No session | Start from a clean baseline **before** editing. If work already began, recover the intended original baseline manually; don't pretend current HEAD was the start. |
| A session already exists | Check `session status`, review the existing session, then deliberately start the next one. |
| PinWash changed since start | Restore the recorded installation/runtime. Do not reset the baseline to silence the error. |
| Review exit 1: blocking changes | Inspect the listed changes, restore unintended weakening or review the intended replacement, then review again. |
| Review exit 2: unfinished | Resolve the reported error and rerun. Observed findings still matter; this is not a pass. |
| Review exit 3: new exemption | Have a human assess its exact scope, reason and expiry before it enters a future baseline. |
| Review exit 0 with coverage/configuration warnings | Inspect those warnings manually. Unassessed items are not passes. |
| Status exit 0 | Only the metadata read succeeded. A historical pass is not a review of current changes. |

PinWash covers supported repository files, not home-directory or service
settings, and a pass does not prove your tests ran or your product works.
Local state and installation must be protected separately if the agent shares
your OS account. See [session behavior](SESSIONS.md) for limits and JSON details.
