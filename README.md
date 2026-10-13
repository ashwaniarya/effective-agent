# effective-agent

### Guardrails that make AI coding agents tell you the risk before they act.

Each guardrail is one file you install with one paste into Claude Code.

## risk-flag

Your agent stops before it deploys, deletes data, spends money, or publishes, and tells you what could break, who gets hit, and how to undo it. Nothing risky runs until you say so.

![Left: Claude Code stops before a production deploy because a migration is pending. Right: it refuses a permanent DELETE on the production users table because there is no backup and no schema.](hooks/risk-flag/example.png)

<sub>Real Claude Code sessions with risk-flag installed. The scripts are stubs, so nothing was deployed or deleted.</sub>

**Install:** copy this, paste it into Claude Code, then restart Claude Code when it says so.

```text
Install the risk-flag hook from https://github.com/ashwaniarya/effective-agent

1. Clone the repo into a temp folder.
2. Copy hooks/risk-flag/risk-flag.js to ~/.claude/hooks/risk-flag.js (create the folder if needed).
3. Merge hooks/risk-flag/settings.snippet.json into ~/.claude/settings.json. Keep all my existing
   hooks and settings: add the new entries to my existing PreToolUse and UserPromptSubmit arrays.
4. Run node hooks/risk-flag/smoke-test.js in the clone and show me the output. Expect 7 OK lines.
5. Tell me to restart Claude Code.
```

**[Full details: what it catches, examples, limits →](hooks/risk-flag)**

## All hooks

| Hook | What it does |
|------|--------------|
| [risk-flag](hooks/risk-flag) | Blocks deploys, prod data changes, payments, releases and hard resets until the agent writes 🟥 / 🟧 / 🟨 risk, blast radius, undo, and waits for your OK. Works even in bypass mode. |
