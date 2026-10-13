# risk-flag

A Claude Code hook that makes the agent say the risk out loud before it acts.

It has two parts, both in one file:

- **Prompt hook** (`UserPromptSubmit`): re-injects a short rule every turn. The agent must write a flag before any risky step.
- **Command hook** (`PreToolUse` on `Bash`): inspects each shell command. If it is risky, the command is denied until the agent flags it and re-runs it with `RISK_ACK=<tier>`.

## Tiers

| Tier | Meaning | The agent must write |
|------|---------|----------------------|
| 🟥 HIGH | prod or staging change, data writes, migrations, killing processes, deploys, publishes, `sudo` | risk, blast radius, undo, gate |
| 🟧 WARNING | money or credits spent (paid APIs, cloud, payments) | cost, cap, gate |
| 🟨 CAUTION | recoverable only with effort (`git reset --hard`, `rm -r`, rebase) or outward-facing (merge, post) | one line: what, why, undo |

The gate defaults to "wait for the user's OK". The agent may add `RISK_ACK` only when the user asked for exactly that step.

## Install

Needs Node 18+ and Claude Code.

1. Copy the hook:

```bash
mkdir -p ~/.claude/hooks && cp hooks/risk-flag/risk-flag.js ~/.claude/hooks/risk-flag.js
```

2. Merge [settings.snippet.json](settings.snippet.json) into `~/.claude/settings.json`. If you already have `PreToolUse` or `UserPromptSubmit` entries, add these items to the existing arrays. Do not replace them.

3. Check it works:

```bash
node hooks/risk-flag/smoke-test.js
```

You should see `OK` on all 7 lines. Start a new Claude Code session so the settings reload.

## Use

Nothing to do. Ask the agent for something risky, for example "restart the production API". It should:

1. Print the flag block first.
2. Wait for your OK.
3. Re-run the command with `RISK_ACK=high` in front once you approve.

A blocked command looks like this in the transcript:

```
🟥 risk-flag HIGH RISK [<rule-id>]: kubectl mutates a cluster. Flag it FIRST with the HIGH RISK block ...
```

## Limits

- It is a guardrail against inattention, not a security boundary. A hostile operator can bypass it.
- It fails open: on any parse or runtime error it lets the command through.
- It only inspects `Bash` commands. Other tools (file edits, MCP calls) are not checked.
- Rules are regex-based. Expect some false positives and misses; tune the rule tables in `risk-flag.js` for your stack.

## Customize

- Production markers (what counts as prod) live in the `PROD_MARKERS` regex near the top of `risk-flag.js`. Add your own hostnames there.
- Per-tool rules (kubectl, terraform, aws, vercel, stripe, and more) live in `INFRA_RULES`.
