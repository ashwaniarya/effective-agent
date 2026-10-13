const { spawnSync } = require("node:child_process");
const path = require("node:path");

const hookPath = path.join(__dirname, "risk-flag.js");

function runHook(payload) {
  const result = spawnSync("node", [hookPath], { input: JSON.stringify(payload), encoding: "utf8" });
  const output = (result.stdout || "").trim();
  return output ? JSON.parse(output) : null;
}

function bash(command) {
  return { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, cwd: "/tmp" };
}

const cases = [
  { name: "harmless command passes", command: "ls -la", expect: "pass" },
  { name: "prod kubectl delete is denied", command: "kubectl delete pod web-1 -n prod", expect: "deny" },
  { name: "prod kubectl delete with ack passes", command: "RISK_ACK=high kubectl delete pod web-1 -n prod", expect: "ack" },
  { name: "money command is denied", command: "stripe refunds create --charge ch_1", expect: "deny" },
  { name: "hard reset is denied", command: "git reset --hard HEAD~1", expect: "deny" },
  { name: "ack below detected tier is denied", command: "RISK_ACK=caution kubectl delete pod web-1 -n prod", expect: "deny" },
];

let failed = 0;
for (const testCase of cases) {
  const result = runHook(bash(testCase.command));
  const decision = result?.hookSpecificOutput?.permissionDecision;
  const actual = decision === "deny" ? "deny" : result?.systemMessage ? "ack" : "pass";
  const ok = actual === testCase.expect;
  if (!ok) failed++;
  console.log(`${ok ? "OK " : "!! "} ${testCase.name} (expected ${testCase.expect}, got ${actual})`);
}

const promptResult = runHook({ hook_event_name: "UserPromptSubmit", prompt: "hello" });
const promptOk = promptResult?.hookSpecificOutput?.additionalContext?.includes("RISK FLAG");
if (!promptOk) failed++;
console.log(`${promptOk ? "OK " : "!! "} prompt hook injects the flag rule`);

process.exit(failed ? 1 : 0);
