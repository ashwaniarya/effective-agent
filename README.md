# effective-agent

Small, copy-paste guardrails for AI coding agents. Each one is a single file you install in two minutes.

AI agents act fast and explain later. These hooks flip that: the agent has to say what could go wrong **before** it acts.

## Hooks

| Hook | Problem it solves | Install |
|------|-------------------|---------|
| [risk-flag](hooks/risk-flag) | The agent deploys, deletes data, spends money, or publishes before you notice. It now flags 🟥 high, 🟧 warning, or 🟨 caution risk first (risk, blast radius, undo, gate), and the command is blocked until it does. | [One prompt](hooks/risk-flag#install) |

## Quick start

Paste this into Claude Code:

```
Install the risk-flag hook from https://github.com/ashwaniarya/effective-agent
Clone it to a temp folder, copy hooks/risk-flag/risk-flag.js to ~/.claude/hooks/, merge
hooks/risk-flag/settings.snippet.json into ~/.claude/settings.json without removing my
existing hooks, run the smoke test, then tell me to restart Claude Code.
```

Each hook is one self-contained folder with its own README (value, use cases, install, limits) and a smoke test.
