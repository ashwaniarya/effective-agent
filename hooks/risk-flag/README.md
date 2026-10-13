# risk-flag

**Make Claude Code say what could go wrong before it deploys, deletes, spends money, or publishes.**

One file. Two minutes to install. Works with any project.

## Why

Claude Code runs shell commands faster than you can read them. A permission prompt shows you the command, not the consequence. If you auto-approve, or you are not watching, `terraform apply` and `git reset --hard` look as routine as `ls`.

risk-flag adds a checkpoint that costs the agent one paragraph and costs you nothing when the command is harmless:

- Before a risky step, the agent must write down the **risk**, the **blast radius**, the **undo path**, and the **gate** (who approves).
- The command itself is blocked until it does. The agent cannot skip the flag by being in a hurry.
- It still holds in `--dangerously-skip-permissions` (bypass) mode. Tested on Claude Code 2.1.291: with `permissionMode=bypassPermissions`, `git reset --hard HEAD` was denied and the uncommitted file was untouched.
- Harmless commands (`ls`, `grep`, tests, local edits) pass straight through.

## What you see

A risky request, for example "restart the production API":

```diff
🟥 HIGH RISK  restart production API
- risk : in-flight requests dropped during restart
- blast: every user of the API, about 30s
- undo : redeploy the previous image
- gate : waiting for your OK
```

If the agent tries the command without writing that first, the hook denies it:

```
🟥 risk-flag HIGH RISK [infra]: kubectl mutates a cluster. Flag it FIRST with the HIGH RISK block
(risk / blast / undo / gate). gate defaults to 'waiting for your OK': re-run with RISK_ACK=high
as the leading assignment ONLY if the user explicitly asked for exactly this step; otherwise stop here.
```

After you approve, the agent re-runs the command with `RISK_ACK=high` in front and it goes through.

## Use cases

| You ask the agent to | What the hook catches | Tier |
|----------------------|-----------------------|------|
| "Restart the production API" or `kubectl delete pod ... -n prod` | Change to a live cluster | 🟥 HIGH |
| "Apply the infra changes" (`terraform apply`) | Real infrastructure changes | 🟥 HIGH |
| "Release 2.0" (`npm publish`) | Public production release | 🟥 HIGH |
| "Refund that charge" (`stripe refunds create`) | Money moving | 🟧 WARNING |
| "Backfill every account" or a paid-API scrape | Credits spent, no cap | 🟧 WARNING |
| "Clean up my branch" (`git reset --hard`) | Uncommitted work lost | 🟨 CAUTION |
| "Merge the PR" (`gh pr merge`) | Outward-facing, only undoable by revert | 🟨 CAUTION |

Good fit if you:

- let Claude Code run unattended or in long sessions,
- have cloud CLIs, `kubectl`, or production credentials on the same machine,
- call paid APIs from scripts the agent writes and runs,
- are onboarding a team to Claude Code and want a shared safety floor.

## Install

**Fastest: paste this into Claude Code.**

```
Install the risk-flag hook from https://github.com/ashwaniarya/effective-agent

1. Clone the repo into a temp folder.
2. Copy hooks/risk-flag/risk-flag.js to ~/.claude/hooks/risk-flag.js (create the folder if needed).
3. Merge hooks/risk-flag/settings.snippet.json into ~/.claude/settings.json. Keep all my existing
   hooks and settings: add the new entries to my existing PreToolUse and UserPromptSubmit arrays.
4. Run node hooks/risk-flag/smoke-test.js in the clone and show me the output. Expect 7 OK lines.
5. Tell me to restart Claude Code.
```

Then restart Claude Code so it reloads settings. Done.

<details>
<summary>Manual install</summary>

Needs Node 18+ and Claude Code.

1. Copy the hook:

```bash
mkdir -p ~/.claude/hooks && cp hooks/risk-flag/risk-flag.js ~/.claude/hooks/risk-flag.js
```

2. Merge [settings.snippet.json](settings.snippet.json) into `~/.claude/settings.json`. If you already have `PreToolUse` or `UserPromptSubmit` entries, add these items to the existing arrays. Do not replace them.

3. Check it works, then start a new Claude Code session:

```bash
node hooks/risk-flag/smoke-test.js
```

</details>

**Uninstall:** delete `~/.claude/hooks/risk-flag.js` and the two entries that run it from `~/.claude/settings.json`.

## Try it

In a new session, ask for something risky, for example "restart the production API", or "git reset --hard to the last commit". The agent should print the flag and wait for your OK. Then ask for `ls`. Nothing happens, as it should.

## How it works

One script, two Claude Code hook events:

- **`UserPromptSubmit`** re-injects a short rule every turn: flag before you act. This catches risks that have no command, like skipping an agreed step or assuming something unverified near production.
- **`PreToolUse` on `Bash`** reads each command and denies risky ones until the agent re-runs it with `RISK_ACK=<tier>`. The parser handles quotes, `bash -c`, `eval`, and `$(...)`.

The agent may add `RISK_ACK` only after writing the flag, and only when you asked for exactly that step.

## Tiers

| Tier | Meaning | The agent must write |
|------|---------|----------------------|
| 🟥 HIGH | prod or staging change, data writes, migrations, killing processes, deploys, publishes, `sudo` | risk, blast radius, undo, gate |
| 🟧 WARNING | money or credits spent (paid APIs, cloud, payments) | cost, cap, gate |
| 🟨 CAUTION | recoverable only with effort (`git reset --hard`, `rm -r`, rebase) or outward-facing (merge, post) | one line: what, why, undo |

The gate defaults to "wait for the user's OK".

## Limits

- It is a guardrail against inattention, not a security boundary. A hostile operator can bypass it.
- It fails open: on any parse or runtime error it lets the command through.
- It only inspects `Bash` commands. Other tools (file edits, MCP calls) are not checked.
- Rules are regex-based. Expect some false positives and misses; tune the rule tables for your stack.

## Customize

- Production markers (what counts as prod) live in the `PROD_MARKERS` regex near the top of `risk-flag.js`. Add your own hostnames there.
- Per-tool rules (kubectl, terraform, aws, vercel, stripe, and more) live in `INFRA_RULES`.
