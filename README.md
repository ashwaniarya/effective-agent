# effective-agent

Small, copy-paste guardrails for AI coding agents.

## Hooks

| Hook | What it does |
|------|--------------|
| [risk-flag](hooks/risk-flag) | Agent flags the risk (🟥 high, 🟧 warning, 🟨 caution) before it deploys, writes data, spends money, or deletes things. |

Each hook is one self-contained folder with its own README, install steps and smoke test.
