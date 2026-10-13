#!/usr/bin/env node
/*
 * risk-flag.js — one hook, two events, three tiers.
 *  UserPromptSubmit : re-injects the RISK FLAG rule so risky strategies get flagged before Claude acts.
 *  PreToolUse(Bash) : denies matching commands until re-run with a leading RISK_ACK=<tier> (or a trailing
 *                     "# RISK_ACK=<tier>"), tier >= the detected one, so the flag precedes the action.
 * Tiers: high (prod/staging, data changes, machine/server/process kills) > warn (money or credits)
 *        > caution (local, recoverable, or outward-facing). Prod/staging markers escalate environment-
 *        touching hits to high; local ops on things merely named "prod" are not escalated.
 * Parsing is quote-aware, follows bash -c / eval / $(...) one level down, normalises the lead command
 * (path, case, quotes), and skips the body of heredocs that only write a file (cat/tee > file).
 * Fails OPEN on any parse or runtime error. Not a security boundary against a hostile operator: a
 * guardrail against inattention.
 */

const path = require("path");
const { execFileSync } = require("child_process");

const TIER_RANK = { caution: 1, warn: 2, high: 3 };
const TIER_LABEL = { caution: "CAUTION", warn: "WARNING", high: "HIGH RISK" };
const TIER_EMOJI = { caution: "🟨", warn: "🟧", high: "🟥" };
const ACK_LEADING = /^(?:\s*[A-Za-z_]\w*=\S*\s+)*RISK_ACK=(high|warn|caution)(?=\s)/;
const ACK_TRAILING = /#\s*RISK_ACK=(high|warn|caution)\s*$/;
const MAX_NESTING = 2;

const ENV_ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
const WRAPPERS = /^(env|command|builtin|time|nice|nohup|exec|timeout|caffeinate|ionice|stdbuf|unbuffer|busybox|toybox)$/;
const WRAPPER_ARG = /^-|^\d+(\.\d+)?[smhd]?$/;
const GIT_CONTROL = /^(--abort|--continue|--skip|--quit|--edit-todo|--show-current-patch|--help|-h)$/;
const TEMP_PATH = /^(\/private)?\/tmp\/|^"?\$\{?(TMPDIR|TMP|TEMP|SCRATCH\w*)\}?/;
const SAFE_RM_BASENAME = /^(node_modules|\.next|\.nuxt|\.turbo|\.cache|\.parcel-cache|\.pytest_cache|\.mypy_cache|\.ruff_cache|__pycache__|dist|build|out|coverage|target|\.venv|venv|\.tox|\.eggs|[^/]*\.egg-info|\.DS_Store|\*\.(pyc|pyo|orig|rej|swp|tmp))$/;
const DATA_TARGET = /\.(db|sqlite3?|sql|dump|pgdump|bak|backup|csv|tsv|parquet|ndjson|jsonl)$|(^|\/)(pgdata|postgres(ql)?[-_]?data|mysql[-_]?data|redis[-_]?data|data|backups?|dumps?|uploads?|storage|media)(\/|$)/i;
const SYSTEM_ROOT = /^\/(Users|home)\/[^/]+\/?$|^\/[^/]+\/?$|^\/(Applications|Library|System|usr|etc|var|opt|bin|sbin|private)(\/|$)/;
const LOCAL_URL = /^https?:\/\/(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|::1|host\.docker\.internal|[\w.-]+\.(localhost|local|internal))(:\d+)?([/?#]|$)/i;
const LOCAL_HOST = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|host\.docker\.internal|[\w.-]+\.(localhost|local|internal))(:\d+)?(\/|$)/i;
const SCHEMELESS_HOST = /^[a-z0-9][\w-]*(\.[\w-]+)+(:\d+)?(\/\S*)?$/i;
const NOT_A_HOST = /\.(json|txt|csv|xml|yaml|yml|sh|py|js|ts|md|html|pem|crt|key|env)$/i;
const PROTECTED_BRANCH = /^(main|master|production|prod|staging|stage|live)$/;
const INTEGRATION_BRANCH = /^(dev|develop|development|release(\/.*)?)$/;
const DEPLOY_REMOTE = /^(heroku|dokku|production|prod|staging|live|deploy|deis|caprover|render)$/;
const DOTENV_FILE = /(^|\/)\.env([-.](?!example|sample|template)[\w.-]+)?$/;

const PROD_MARKERS = /\b(prod|production|staging)\b|[-_.](prod|production|staging)[-_.]|\b(PROD(UCTION)?|STAGING)_|--live\b|\b[sprk]k_live_/i;
const MONEY_MARKERS = /scrapingbee|dataforseo|serpapi|serper|openai|anthropic|api\.openai\.com|api\.anthropic\.com|generativelanguage|replicate\.com|elevenlabs|twilio|sendgrid|mailgun|resend\.com|postmark|stripe|paddle|lemonsqueezy|braintree|--live\b|run-instances|droplet\s+create|create-droplet|instances\s+create|\benrich|\bbackfill|\bscrape|\bsweep\b|\bcrawl/i;
const READ_ONLY_LEAD = /^(grep|rg|ag|cat|bat|less|more|head|tail|awk|sed|echo|printf|ls|find|wc|sort|uniq|jq|yq|git|gh|man|which|whereis|type|hash|file|stat|du|df|tree|diff|cmp|md5|shasum|cd|pushd|popd|mkdir|touch|cp|mv|ln|chmod|chown|test|\[|true|false|sleep|date|export|source|\.|env|printenv|history|alias|vim|vi|nvim|nano|emacs|subl|cursor|code|open|tar|zip|unzip|gzip|pytest|jest|vitest|mocha|tsc|eslint|ruff|mypy|black|prettier|pip3?|brew|cargo|gem|poetry|uv|pipx|curl|wget|http|https|xh|psql|pgcli|mysql|sqlite3|redis-cli|mongosh|duckdb)$/;
const RUNNER_LEAD = /^(python3?|node|npx|bun|deno|uv|poetry|pipenv|bash|sh|zsh|make)$/;
const TEST_RUN = /\b(pytest|unittest|jest|vitest|mocha|-m\s+pytest|npm\s+test|test_[\w-]+\.py|\.test\.[jt]sx?|\.spec\.[jt]sx?)\b/;
const ENV_SENSITIVE_RULES = new Set(["remote", "sql", "http", "transfer", "money", "docker", "infra", "prod-run", "inline", "deploy"]);

const RULE_TEXT = [
  "RISK FLAG (hook, every turn). Flag BEFORE acting, one per step, never soften it.",
  "",
  "\ud83d\udfe5 HIGH = prod or staging change; data writes, DDL, migrations, data files; killing machines, services, containers, processes; sudo; disk ops; deploys and publishes; main-branch guard bypass.",
  "  Emit: \ud83d\udfe5 **HIGH RISK** <action>, then a ```diff fence with the lines \"- risk :\", \"- blast:\", \"- undo :\", \"- gate :\". gate defaults to waiting for your OK; proceed only if the user asked for exactly this step.",
  "",
  "\ud83d\udfe7 WARNING = money or credits spent (paid APIs, cloud, payment processors, enrichment, backfill, scrape runs).",
  "  Emit: \ud83d\udfe7 **WARNING** <action>, then a ```diff fence with \"! cost :\", \"! cap  :\", \"! gate :\". Afterwards: \ud83d\udfe7 spent: <amount>.",
  "",
  "\ud83d\udfe8 CAUTION = local but recoverable only with effort (rm -r, reset --hard, checkout ., clean, branch -D, rebase, force-push to a feature branch, sed -i over globs, hook bypass, .env exposure, single-process kill) or outward-facing (merge, post, message).",
  "  Emit one line: \ud83d\udfe8 **CAUTION** <what and why> \u00b7 undo: <rollback or none>. Proceeds, except outward-facing steps wait unless asked for exactly that.",
  "",
  "Strategy risks with no command (deviating from the agreed approach, an unverified assumption at a decision point, fixing a symptom not the cause, editing the wrong checkout) are \ud83d\udfe8, or \ud83d\udfe5 when prod or data is involved.",
  "Bash: denied until re-run with RISK_ACK=high|warn|caution as the leading assignment (or '# RISK_ACK=<tier>' trailing), tier at or above the denied tier. Write the flag first; never add RISK_ACK without it.",
].join("\n");

const REMOTE_MUTATION = new RegExp(
  [
    "\\b(rm|mv|cp|tee|dd|truncate|shred|chmod|chown|chgrp|ln|kill|pkill|killall|reboot|shutdown|halt|poweroff|systemctl|service|supervisorctl|pm2|crontab|useradd|userdel|usermod|passwd|iptables|ufw|nft|certbot|visudo|mkfs|fdisk|parted|sudo|su)\\b",
    "\\b(docker|podman)(-compose)?\\s+(compose\\s+)?(up|down|restart|build|pull|push|rm|rmi|kill|stop|start|run|exec|cp|update|system|volume|network|prune|login)\\b",
    "\\bkubectl\\s+(apply|delete|patch|scale|rollout|edit|replace|drain|create)\\b",
    "\\b(apt|apt-get|yum|dnf|apk|snap|brew)\\s+(install|remove|purge|upgrade|update|autoremove|uninstall)\\b",
    "\\b(pip3?|npm|pnpm|yarn|bun)\\s+(install|uninstall|i|ci|add|remove|update|upgrade|run)\\b",
    "\\bgit\\s+(pull|fetch|checkout|switch|reset|merge|rebase|clean|stash|push|commit|cherry-pick|revert|am)\\b",
    "\\b(psql|mysql|mongosh?|redis-cli|sqlite3)\\b",
    "\\bsed\\s+-[a-zA-Z]*i\\b",
    "\\b(curl|wget)\\b[^;&|]*(\\s-X\\s*(POST|PUT|PATCH|DELETE)|\\s(-d|--data\\S*|-F|-T|--json)\\b|\\s--method[= ](POST|PUT|PATCH|DELETE)|--post-data)",
    "(^|[^>])>(?!>?\\s*(/dev/null|&\\d))",
    "(^|\\s)<\\s*\\S",
    "\\$\\(|`",
    "\\b(make|bash\\s+-[cs]|sh\\s+-[cs]|zsh\\s+-c|bash\\s+\\S+\\.sh|sh\\s+\\S+\\.sh)\\b",
    "\\b(python3?|node|ruby|perl|php)\\s+\\S+",
    "(^|\\s)\\./\\S+",
  ].join("|"),
  "i"
);

const INFRA_RULES = [
  ["high", /^kubectl$/, /^(delete|drain|cordon|uncordon|apply|replace|patch|scale|rollout|edit|taint|create)\b/, "kubectl mutates a cluster"],
  ["high", /^helm$/, /^(install|upgrade|uninstall|delete|rollback)\b/, "helm mutates a cluster release"],
  ["high", /^(terraform|tofu)$/, /^(apply|destroy|import|taint|untaint|force-unlock|state\s+(rm|mv|push|replace-provider))\b/, "terraform changes real infrastructure"],
  ["high", /^pulumi$/, /^(up|destroy|refresh|import|state)\b/, "pulumi changes real infrastructure"],
  ["high", /^aws$/, /\b(rm|rb|mv|delete|terminate|reboot|stop|revoke|detach|deregister|deactivate|purge|put-bucket-policy|put-bucket-acl|iam|run-instances|create-)\b|--delete\b/, "aws CLI mutates infrastructure, data or IAM"],
  ["high", /^gcloud$/, /\b(delete|destroy|remove|reset|revoke|purge|deploy|create|set-iam-policy|add-iam-policy-binding|remove-iam-policy-binding)\b/, "gcloud mutates infrastructure, IAM or a deploy"],
  ["high", /^az$/, /\b(delete|destroy|remove|purge|deploy|create|role\s+assignment)\b/, "az mutates infrastructure, IAM or a deploy"],
  ["high", /^doctl$/, /\b(delete|destroy|create|create-deployment|update|deploy|rollback|power-off|reboot)\b/, "doctl deploys, creates or destroys on DigitalOcean"],
  ["high", /^(vercel|now)$/, /--prod\b|\b(promote|rollback|rm|remove|alias|redeploy|env\s+(add|rm|remove)|domains\s+(add|rm))\b/, "vercel production deploy or config change"],
  ["high", /^netlify$/, /\bdeploy\b.*--prod|\b(sites:delete|env:(set|unset|import)|rollback)\b/, "netlify production deploy or config change"],
  ["high", /^(fly|flyctl)$/, /^(deploy|destroy|scale|secrets\s+(set|unset|import)|apps\s+destroy|volumes\s+destroy|machine\s+(destroy|kill|remove|stop|restart))\b/, "fly deploy, destroy or machine kill"],
  ["high", /^heroku$/, /\b(destroy|reset|rollback|config:(set|unset)|restart|scale|maintenance:on|run)\b/, "heroku mutates a running app"],
  ["high", /^wrangler$/, /^(deploy|publish|delete|rollback|secret\s+(put|delete|bulk)|kv:key\s+(put|delete)|d1\s+execute|r2\s+object\s+(put|delete))\b/, "wrangler deploy or data write"],
  ["high", /^firebase$/, /^(deploy|firestore:delete|database:(remove|set|update|push)|functions:delete|hosting:disable)\b/, "firebase deploy or data write"],
  ["high", /^supabase$/, /^(db\s+(reset|push)|functions\s+deploy|secrets\s+set|projects\s+delete|link|unlink|migration\s+repair)\b/, "supabase schema push, reset or deploy"],
  ["warn", /^stripe$/, /\b(create|update|delete|cancel|capture|confirm|refund|trigger)\b/, "stripe CLI write moves money or billing objects"],
  ["high", /^(npm|pnpm|yarn|bun)$/, /^publish\b/, "publishes a package to a public registry (production release)"],
  ["caution", /^(npm|pnpm|yarn|bun)$/, /(^|\s)--force(\s|$)/, "package manager --force overrides dependency resolution"],
  ["high", /^twine$/, /^upload\b/, "publishes a package to PyPI (production release)"],
  ["high", /^poetry$/, /^publish\b/, "publishes a package to PyPI (production release)"],
  ["high", /^cargo$/, /^publish\b/, "publishes a crate (production release)"],
  ["high", /^gem$/, /^push\b/, "publishes a gem (production release)"],
  ["caution", /^gh$/, /^pr\s+merge\b/, "gh pr merge lands on the base branch, only undoable by revert (outward-facing)"],
  ["caution", /^gh$/, /^(repo\s+(delete|archive|rename|edit|sync)|release\s+(create|delete|upload|edit)|secret\s+(set|delete|remove)|variable\s+(set|delete)|pr\s+review\s+.*--approve|pr\s+edit\s+.*--base|issue\s+(delete|transfer)|workflow\s+(run|disable|enable)|run\s+(cancel|rerun|delete)|api\s+.*(-X|--method)[\s=]*(POST|PUT|PATCH|DELETE)|ruleset|label\s+delete|cache\s+delete)\b/, "gh publishes, deletes or reconfigures on GitHub (outward-facing)"],
];

function hit(tier, reason) {
  return { tier, reason };
}

function stripQuotes(value) {
  return String(value || "").replace(/^["'`]+|["'`]+$/g, "");
}

function normalizeLead(token) {
  const bare = String(token || "").replace(/["'\\]/g, "");
  return (bare.split("/").pop() || bare).toLowerCase();
}

function tokenize(text) {
  const tokens = [];
  let current = "";
  let quote = null;
  let depth = 0;
  let inToken = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];
    if (quote) {
      current += ch;
      if (ch === "\\" && quote === '"' && next !== undefined) current += text[++i];
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "\\" && next !== undefined) {
      current += ch + next;
      i++;
      inToken = true;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      current += ch;
      inToken = true;
      continue;
    }
    if (ch === "$" && next === "(") {
      depth++;
      current += "$(";
      i++;
      inToken = true;
      continue;
    }
    if (depth > 0) {
      if (ch === "(") depth++;
      else if (ch === ")") depth--;
      current += ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (inToken) tokens.push(current);
      current = "";
      inToken = false;
      continue;
    }
    current += ch;
    inToken = true;
  }
  if (inToken) tokens.push(current);
  return tokens;
}

function splitSegments(text) {
  const segments = [];
  let current = "";
  let quote = null;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];
    if (quote) {
      current += ch;
      if (ch === "\\" && quote === '"' && next !== undefined) current += text[++i];
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "\\" && next !== undefined) {
      current += ch + next;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "$" && next === "(") {
      depth++;
      current += "$(";
      i++;
      continue;
    }
    if (depth > 0) {
      if (ch === "(") depth++;
      else if (ch === ")") depth--;
      current += ch;
      continue;
    }
    if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) {
      segments.push(current);
      current = "";
      i++;
      continue;
    }
    if (ch === ";" || ch === "|" || ch === "\n" || ch === "&") {
      segments.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  segments.push(current);
  return segments.map((s) => s.trim()).filter(Boolean);
}

function substitutionBodies(text) {
  const bodies = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "$" && text[i + 1] === "(") {
      let depth = 1;
      let j = i + 2;
      while (j < text.length && depth > 0) {
        if (text[j] === "(") depth++;
        else if (text[j] === ")") depth--;
        j++;
      }
      bodies.push(text.slice(i + 2, depth === 0 ? j - 1 : j));
      i = j - 1;
    } else if (text[i] === "`") {
      const j = text.indexOf("`", i + 1);
      if (j === -1) break;
      bodies.push(text.slice(i + 1, j));
      i = j;
    }
  }
  return bodies;
}

function leadTokens(segment) {
  const all = tokenize(segment.replace(/^[({\s]+/, ""));
  let i = 0;
  while (i < all.length) {
    if (ENV_ASSIGN.test(all[i])) {
      i++;
      continue;
    }
    const word = normalizeLead(all[i]);
    if (WRAPPERS.test(word)) {
      i++;
      while (i < all.length && (WRAPPER_ARG.test(all[i]) || ENV_ASSIGN.test(all[i]))) i++;
      continue;
    }
    if (word === "xargs") {
      i++;
      while (i < all.length && (/^-/.test(all[i]) || /^\{\}$/.test(all[i]) || /^\d+$/.test(all[i]))) i++;
      continue;
    }
    break;
  }
  const tokens = all.slice(i);
  if (tokens.length) {
    tokens.leadRaw = tokens[0];
    tokens[0] = normalizeLead(tokens[0]);
  }
  return tokens;
}

function positionalArgs(tokens) {
  return tokens.filter((a) => !/^-/.test(a)).map(stripQuotes).filter(Boolean);
}

function nestedTexts(tokens, segment) {
  const out = [];
  const lead = tokens[0];
  if (/^(bash|sh|zsh|dash|ksh|fish)$/.test(lead)) {
    const idx = tokens.findIndex((a, i) => i > 0 && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
    if (idx !== -1 && tokens[idx + 1]) out.push(stripQuotes(tokens[idx + 1]));
  }
  if (lead === "eval") out.push(tokens.slice(1).map(stripQuotes).join(" "));
  if (/^(su|sudo|doas|pkexec)$/.test(lead)) {
    const idx = tokens.indexOf("-c");
    if (idx !== -1 && tokens[idx + 1]) out.push(stripQuotes(tokens[idx + 1]));
    else out.push(tokens.slice(1).filter((a) => !/^-/.test(a)).join(" "));
  }
  const shellC = /(?:^|\s)(?:sh|bash|zsh)\s+-[a-zA-Z]*c[a-zA-Z]*\s+('([^']*)'|"([^"]*)")/g;
  let match;
  while ((match = shellC.exec(segment))) out.push(match[2] !== undefined ? match[2] : match[3]);
  out.push(...substitutionBodies(segment));
  return out.filter((s) => s && s.trim());
}

function resolveDir(current, target) {
  if (!target || target === "-") return current;
  const expanded = target.replace(/^~(?=\/|$)/, process.env.HOME || "~");
  return path.resolve(current || process.cwd(), expanded);
}

function currentBranch(dir) {
  try {
    return execFileSync("git", ["symbolic-ref", "--short", "HEAD"], {
      cwd: dir || process.cwd(),
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2000,
      encoding: "utf8",
    }).trim();
  } catch {
    return "";
  }
}

function isSafeRmTarget(target) {
  if (TEMP_PATH.test(target)) return true;
  const trimmed = target.replace(/\/+\*{1,2}$/, "").replace(/\/+$/, "");
  if (/\/(node_modules|__pycache__|\.next|dist|build|\.cache)\//.test(trimmed + "/")) return true;
  return SAFE_RM_BASENAME.test(trimmed.split("/").pop());
}

function coversWorkingDir(target, cwd) {
  if (!cwd || !target || /[*?$]/.test(target)) return false;
  const resolved = resolveDir(cwd, target).replace(/\/+$/, "");
  return cwd === resolved || cwd.startsWith(resolved + "/");
}

function rmRule(t, segment, cwd) {
  if (t[0] !== "rm") return null;
  const flags = t.slice(1).filter((a) => /^-/.test(a));
  const targets = positionalArgs(t.slice(1));
  const recursive = flags.some((f) => /^-[a-zA-Z]*[rR]/.test(f) || f === "--recursive");
  const wildcard = targets.some((x) => /[*?]/.test(x));
  if (!recursive && !wildcard) return null;
  if (targets.length && targets.every(isSafeRmTarget)) return null;
  const danger = targets.filter((x) => /^(\/|~[^/]*|\.|\.\.|\$\{?HOME\}?|\/\*|~\/\*|\*)\/?$/.test(x) || SYSTEM_ROOT.test(x) || coversWorkingDir(x, cwd));
  if (danger.length) return hit("high", "recursive delete of root, home, a system dir, or the working directory (" + danger.join(" ") + ")");
  const data = targets.filter((x) => DATA_TARGET.test(x));
  if (data.length) return hit("high", "deletes data files or a data directory (" + data.join(" ") + ")");
  let why = recursive ? "recursive delete" : "wildcard delete";
  if (targets.some((x) => /\$/.test(x))) why += " with a variable-expanded target (an empty var becomes rm -rf /)";
  return hit("caution", why + " outside build caches and temp dirs: unrecoverable");
}

function findRule(t, segment) {
  if (t[0] !== "find") return null;
  if (t.includes("-delete")) return hit("caution", "find -delete: bulk unrecoverable delete");
  if (/-(exec|execdir|ok)\s+(rm|shred|unlink)\b/.test(segment)) return hit("caution", "find -exec rm: bulk unrecoverable delete");
  if (/-(exec|execdir)\s+(sed|gsed|perl)\s+-[a-zA-Z]*i/.test(segment)) return hit("caution", "find -exec sed -i: bulk in-place edit across files");
  return null;
}

function killRule(t, segment) {
  const c = t[0];
  const positional = positionalArgs(t);
  if (/^(pkill|killall)$/.test(c)) return hit("high", c + " kills programs by name");
  if (c === "kill") {
    if (t.includes("-1")) return hit("high", "kill -1 kills every process you own");
    if (/\$\(\s*pgrep\b|`\s*pgrep\b/.test(segment)) return hit("high", "kill $(pgrep ...) kills programs by name");
    return hit("caution", "kill stops a local process by pid");
  }
  if (/^(shutdown|reboot|halt|poweroff)$/.test(c)) return hit("high", c + " takes the machine down");
  if (c === "init" && /^[06]$/.test(t[1] || "")) return hit("high", "init " + t[1] + " takes the machine down");
  if (c === "systemctl" && /^(poweroff|reboot|halt|kexec|stop|restart|kill|disable|mask|isolate)$/.test(positional[1] || "")) return hit("high", "systemctl " + positional[1] + " stops or restarts a service or the machine");
  if (c === "service" && /^(stop|restart|reload|force-reload)$/.test(positional[2] || "")) return hit("high", "service " + positional[2] + " stops or restarts a daemon");
  if (c === "launchctl" && /^(bootout|unload|remove|kill|stop|disable)$/.test(positional[1] || "")) return hit("high", "launchctl " + positional[1] + " stops a launchd service");
  if (c === "brew" && positional[1] === "services" && /^(stop|restart|kill)$/.test(positional[2] || "")) return hit("high", "brew services " + positional[2] + " stops or restarts a service");
  if (c === "pm2" && /^(stop|restart|delete|kill|reload)$/.test(positional[1] || "")) return hit("high", "pm2 " + positional[1] + " stops or restarts a process");
  if (c === "supervisorctl" && /^(stop|restart|shutdown)$/.test(positional[1] || "")) return hit("high", "supervisorctl " + positional[1] + " stops or restarts a process");
  return null;
}

function systemRule(t, segment) {
  const c = t[0];
  if (/^(sudo|su|doas|pkexec)$/.test(c)) return hit("high", c + " runs with elevated or another user's privileges");
  if (/^(shred|wipefs|mkfs(\.\w+)?)$/.test(c)) return hit("high", c + " destroys data irrecoverably");
  if (c === "dd" && t.some((a) => /^of=\/dev\//.test(a))) return hit("high", "dd writes onto a raw device");
  if (c === "diskutil" && /^(erase|partition|reformat|secure|zero|apfs\s+delete)/i.test(t.slice(1).join(" "))) return hit("high", "diskutil erase or partition destroys a volume");
  if (c === "crontab" && t.includes("-r")) return hit("high", "crontab -r wipes every scheduled job on this machine");
  if (c === "chmod" && t.includes("777")) return hit("caution", "chmod 777 makes files world-writable");
  if (/^(csrutil|spctl|pfctl|networksetup)$/.test(c)) return hit("high", c + " changes macOS system or security settings");
  if (c === "security" && /^(add|delete|set|import|unlock|create)/.test(t[1] || "")) return hit("high", "security (keychain) write");
  if (c === "osascript" && /(Mail|Messages|Slack|Discord|WhatsApp|Telegram)/.test(segment)) return hit("caution", "osascript drives a messaging app and could send a message (outward-facing)");
  if (/^(cat|bat|less|more|head|tail)$/.test(c) && positionalArgs(t.slice(1)).some((a) => DOTENV_FILE.test(a))) return hit("caution", "dumps a .env file (secrets) into the transcript");
  return null;
}

function gitRule(t, cwd) {
  if (t[0] !== "git") return null;
  let i = 1;
  let dir = null;
  while (i < t.length && /^-/.test(t[i])) {
    if (/^(-C|-c|--git-dir|--work-tree|--namespace)$/.test(t[i])) {
      if (t[i] === "-C") dir = stripQuotes(t[i + 1]);
      i += 2;
    } else {
      i++;
    }
  }
  if (t.some((a) => /^core\.hooksPath=/i.test(stripQuotes(a)))) return hit("caution", "git -c core.hooksPath bypasses the repo's git hooks");
  const sub = t[i];
  const args = t.slice(i + 1);
  const has = (re) => args.some((a) => re.test(a));
  const positional = positionalArgs(args);
  const caution = (reason) => hit("caution", reason);
  switch (sub) {
    case "push": {
      const remote = positional[0] || "";
      const refspecs = positional.slice(1);
      let branch = null;
      const resolveTarget = (r) => {
        let target = r.includes(":") ? r.split(":").pop() : r;
        target = target.replace(/^\+/, "").replace(/^refs\/heads\//, "");
        if (target === "HEAD") {
          if (branch === null) branch = currentBranch(dir || cwd);
          return branch;
        }
        return target;
      };
      const targets = refspecs.filter((r) => !/^\+?:/.test(r)).map(resolveTarget).filter(Boolean);
      if (!refspecs.length && branch === null) branch = currentBranch(dir || cwd);
      const forced = has(/^(-[a-zA-Z]*f[a-zA-Z]*|--force|--force-with-lease(=.*)?|--force-if-includes)$/) || refspecs.some((r) => /^\+/.test(r));
      const deleting = has(/^(-[a-zA-Z]*d[a-zA-Z]*|--delete)$/) || refspecs.some((r) => /^\+?:/.test(r));
      const named = targets.find((b) => PROTECTED_BRANCH.test(b)) || (!refspecs.length && branch && PROTECTED_BRANCH.test(branch) ? branch : null);
      if (named) return hit("high", "git push to protected branch '" + named + "'" + (forced ? " with --force" : "") + ": release path, bypasses the PR flow");
      if (DEPLOY_REMOTE.test(remote)) return hit("high", "git push to remote '" + remote + "' triggers a deploy");
      if (forced) return caution("git push --force rewrites remote history others may have built on");
      if (deleting) return caution("git push --delete removes a remote branch");
      if (has(/^--no-verify$/)) return caution("git push --no-verify skips pre-push hooks");
      const integration = targets.find((b) => INTEGRATION_BRANCH.test(b)) || (!refspecs.length && branch && INTEGRATION_BRANCH.test(branch) ? branch : null);
      if (integration) return caution("git push to integration branch '" + integration + "' bypasses the PR flow");
      return null;
    }
    case "pull":
      return has(/^(-r|--rebase(=.*)?)$/) ? caution("git pull --rebase rewrites local history") : null;
    case "reset":
      return has(/^--hard$/) ? caution("git reset --hard discards uncommitted work") : null;
    case "checkout":
      if (has(/^(-f|--force)$/)) return caution("git checkout --force discards local changes");
      if (positional.some((p) => /^(\.\/?|:\/|\*)$/.test(p))) return caution("git checkout . discards every working-tree change");
      return null;
    case "restore":
      if (has(/^(-S|--staged)$/) && !has(/^(-W|--worktree)$/)) return null;
      if (positional.some((p) => /^(\.\/?|:\/|\*)$/.test(p))) return caution("git restore . discards every working-tree change");
      return null;
    case "clean":
      return has(/^(-[a-zA-Z]*f[a-zA-Z]*|--force)$/) ? caution("git clean -f deletes untracked files") : null;
    case "branch":
      if (has(/^-[a-zA-Z]*D[a-zA-Z]*$/) || (has(/^(-[a-zA-Z]*d[a-zA-Z]*|--delete)$/) && has(/^(-[a-zA-Z]*f[a-zA-Z]*|--force)$/))) return caution("git branch -D force-deletes a branch, unmerged commits lost");
      return null;
    case "stash":
      return /^(drop|clear)$/.test(args[0] || "") ? caution("git stash " + args[0] + " discards stashed work") : null;
    case "worktree":
      return args[0] === "remove" && has(/^(-f|--force)$/) ? caution("git worktree remove --force deletes a worktree with uncommitted changes") : null;
    case "rebase":
      return has(GIT_CONTROL) ? null : caution("git rebase rewrites history");
    case "filter-branch":
    case "filter-repo":
    case "replace":
      return caution("git " + sub + " rewrites history");
    case "commit":
      return has(/^(--no-verify|-n)$/) ? caution("git commit --no-verify skips pre-commit hooks") : null;
    case "add":
      if (has(/^(-f|--force)$/)) return caution("git add --force stages gitignored files (secrets risk)");
      if (positional.some((p) => DOTENV_FILE.test(p))) return caution("git add of a .env file puts secrets into history");
      return null;
    case "reflog":
      return /^(expire|delete)$/.test(args[0] || "") ? caution("git reflog " + args[0] + " destroys recovery points") : null;
    case "gc":
      return has(/^--prune=/) ? caution("git gc --prune destroys unreachable recovery objects") : null;
    case "update-ref":
      return has(/^-d$/) ? caution("git update-ref -d deletes a ref") : null;
    default:
      return null;
  }
}

function dockerRule(t) {
  if (!/^(docker|docker-compose|podman|podman-compose|nerdctl)$/.test(t[0])) return null;
  let rest = t.slice(1).join(" ");
  if (/compose$/.test(t[0])) rest = "compose " + rest;
  if (/\bdown\b/.test(rest) && /(^|\s)(-v|--volumes)(\s|$)/.test(rest)) return hit("high", "compose down -v deletes volumes, database data included");
  if (/\bvolume\s+(rm|prune)\b/.test(rest) || (/\bprune\b/.test(rest) && /--volumes\b/.test(rest))) return hit("high", "docker volume removal deletes persistent data");
  if (/\b(system|image|container|network|builder|buildx)\s+prune\b/.test(rest)) return hit("caution", "docker prune bulk-deletes images or containers");
  if (/^push\b|\bcompose\s+push\b/.test(rest)) return hit("high", "docker push publishes an image to a registry (release artifact)");
  if (/^(stop|kill|restart)\b/.test(rest) || /^rm\b.*(\s-[a-zA-Z]*f|--force)/.test(rest)) return hit("high", "docker " + rest.split(/\s+/)[0] + " kills running containers (process kill)");
  if (/\bcompose\b.*\b(down|stop|restart|kill)\b/.test(rest) || /\bcompose\b.*\brm\b.*(\s-[a-zA-Z]*[fs]|--force|--stop)/.test(rest)) return hit("high", "compose stop/down/restart kills running services (process kill)");
  if (/\bcompose\b.*\bup\b.*--force-recreate/.test(rest)) return hit("high", "compose up --force-recreate kills and recreates running services (process kill)");
  return null;
}

function infraRule(t) {
  const rest = t.slice(1).join(" ");
  for (const [tier, cli, pattern, reason] of INFRA_RULES) {
    if (cli.test(t[0]) && pattern.test(rest)) return hit(tier, reason);
  }
  return null;
}

function deployRule(t) {
  const lead = t[0];
  const rest = t.slice(1).join(" ");
  const deployWord = /^(deploy|release|ship)([_.:-]|$)/i;
  if (/^(npm|pnpm|yarn|bun)$/.test(lead) && /^(run\s+)?(deploy|release|ship)(\b|:)/.test(rest)) return hit("high", "runs a deploy or release script");
  if (lead === "make" && deployWord.test(t[1] || "")) return hit("high", "runs a deploy or release make target");
  if (RUNNER_LEAD.test(lead) && deployWord.test(normalizeLead(t[1] || ""))) return hit("high", "runs a deploy or release script");
  if (/^\.\//.test(t.leadRaw || "") && deployWord.test(lead)) return hit("high", "runs a deploy or release script");
  return null;
}

function transferRule(t) {
  if (!/^(rsync|scp)$/.test(t[0])) return null;
  const positional = positionalArgs(t.slice(1));
  const destination = positional[positional.length - 1] || "";
  const remoteDestination = /^([\w.-]+@)?[\w.-]+:/.test(destination) && !/^[a-zA-Z]:\\/.test(destination);
  if (t[0] === "rsync" && t.some((a) => /^--delete/.test(a))) return hit(remoteDestination ? "high" : "caution", "rsync --delete removes files at the destination" + (remoteDestination ? " on a remote server" : ""));
  if (remoteDestination) return hit("high", t[0] + " upload overwrites files on a remote server");
  return null;
}

function classifyHosts(tokens) {
  const local = [];
  const remote = [];
  let unknown = 0;
  for (const raw of tokens.slice(1)) {
    const a = stripQuotes(raw);
    if (/^-/.test(a) || /^@/.test(a)) continue;
    if (/^https?:\/\//i.test(a)) {
      (LOCAL_URL.test(a) ? local : remote).push(a);
      continue;
    }
    if (/^:\d*(\/|$)/.test(a) || LOCAL_HOST.test(a)) {
      local.push(a);
      continue;
    }
    if (SCHEMELESS_HOST.test(a) && !NOT_A_HOST.test(a.split("/")[0])) {
      remote.push(a);
      continue;
    }
    if (/\$/.test(a) && /\//.test(a)) unknown++;
  }
  return { local, remote, unknown };
}

function httpRule(t) {
  if (!/^(curl|wget|http|https|xh|httpie)$/.test(t[0])) return null;
  const rest = t.slice(1).join(" ");
  const mutating =
    /(^|\s)(-X|--request)[\s=]*(POST|PUT|PATCH|DELETE)\b/i.test(rest) ||
    /(^|\s)(-d|--data|--data-raw|--data-binary|--data-urlencode|-F|--form|-T|--upload-file|--json|--post-data|--post-file)\b/.test(rest) ||
    /(^|\s)--method[\s=]*(POST|PUT|PATCH|DELETE)\b/i.test(rest) ||
    (/^(http|https|xh|httpie)$/.test(t[0]) && /(^|\s)(POST|PUT|PATCH|DELETE)\s/.test(rest));
  if (!mutating) return null;
  const hosts = classifyHosts(t);
  if (!hosts.remote.length && !hosts.unknown && hosts.local.length) return null;
  const where = hosts.remote.length ? " (" + hosts.remote[0] + ")" : " (host hidden behind a variable)";
  if (MONEY_MARKERS.test(rest)) return hit("warn", "mutating HTTP call to a paid service" + where);
  return hit("caution", "mutating HTTP call to a remote service" + where + " (outward-facing)");
}

function sedRule(t, segment) {
  if (!/^(sed|gsed|perl)$/.test(t[0])) return null;
  const inPlace = t.some((a) => /^-[a-zA-Z]*i/.test(a) || /^--in-place/.test(a));
  if (!inPlace) return null;
  if (/^\s*[({]*\s*(\w+=\S*\s+)*xargs\b/.test(segment)) return hit("caution", "xargs sed -i: bulk in-place edit across files");
  let nonFlags = positionalArgs(t.slice(1));
  if (t.indexOf("-e") === -1) nonFlags = nonFlags.slice(1);
  const glob = nonFlags.some((a) => /[*?]/.test(a) || /\{[^}]*,[^}]*\}/.test(a));
  return glob ? hit("caution", "sed -i over a glob: bulk in-place edit across files") : null;
}

function moneyRule(t, segment) {
  const lead = t[0];
  if (READ_ONLY_LEAD.test(lead)) return null;
  if (/^(npm|pnpm|yarn|bun)$/.test(lead) && !/^(run|start|exec|x)$/.test(t[1] || "")) return null;
  if (!MONEY_MARKERS.test(segment)) return null;
  if (TEST_RUN.test(segment) || /--dry-run\b|--dry\b|--plan\b|--noop\b/.test(segment)) return null;
  const marker = (segment.match(MONEY_MARKERS) || [""])[0];
  return hit("warn", "runs something that spends money or credits (" + marker + ")");
}

function prodRunRule(t, segment) {
  if (!PROD_MARKERS.test(segment) || TEST_RUN.test(segment)) return null;
  const lead = t[0];
  const rest = t.slice(1).join(" ");
  if (RUNNER_LEAD.test(lead) || /^\.\//.test(t.leadRaw || "")) return hit("high", "runs a program against a prod or staging target");
  if (/^(npm|pnpm|yarn|bun)$/.test(lead) && /^(run|start|exec|x)$/.test(t[1] || "")) return hit("high", "runs a script against a prod or staging target");
  if (/^(docker|docker-compose|podman)$/.test(lead) && /(^|\s)(up|run|exec|build|pull|start)\b/.test(rest)) return hit("high", "runs containers against a prod or staging target");
  return null;
}

function scriptBodyRule(body, noun) {
  if (/\b(DROP\s+(TABLE|DATABASE|SCHEMA|COLLECTION)|TRUNCATE|DELETE\s+FROM|\.drop\(|\.truncate\(|deleteMany|delete_many|drop_collection|flushall|flushdb)\b/i.test(body)) return hit("high", noun + " issues destructive database statements");
  if (/\b(rmtree|rmSync|rmdirSync|unlinkSync|unlink|os\.remove|os\.rmdir|shutil\.(rmtree|move)|FileUtils\.rm|fs\.rm|remove_tree|unlink_p)\b/.test(body)) return hit("caution", noun + " deletes files");
  if (/\b(subprocess|os\.system|os\.popen|child_process|execSync|spawnSync|spawn|system)\s*[.(]|`/.test(body)) return hit("caution", noun + " spawns shell commands; their content was not scanned");
  return null;
}

function inlineScriptRule(t) {
  if (!/^(python3?|node|ruby|perl|php|deno|bun)$/.test(t[0])) return null;
  const flagIndex = t.findIndex((a, i) => i > 0 && /^(-c|-e|-r|--eval|-p)$/.test(a));
  if (flagIndex === -1) return null;
  return scriptBodyRule(t.slice(flagIndex + 1).map(stripQuotes).join(" "), "inline script");
}

function remoteRule(cmd) {
  const match = cmd.match(/(^|[;&|(]\s*)(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*ssh\s+([\s\S]*)$/);
  if (match && REMOTE_MUTATION.test(match[2])) return hit("high", "ssh runs a mutating command on a remote server");
  return null;
}

const DB_CLIENT = /\b(psql|pgcli|mysql|mariadb|sqlite3|mongosh|mongo|redis-cli|clickhouse-client|duckdb|usql|cockroach|alembic|prisma|supabase|dbmate|flyway|liquibase|goose|sqlx|knex|drizzle-kit|typeorm|sequelize|manage\.py|rails\s+db|flask\s+db)\b|\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|rediss):\/\//i;

function sqlRule(cmd) {
  if (!DB_CLIENT.test(cmd)) return null;
  const high = (reason) => hit("high", reason);
  const realWhere = /\bWHERE\b(?!\s+(1\s*=\s*1|true|1)\b)/i.test(cmd);
  if (/\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|MATERIALIZED\s+VIEW|EXTENSION|ROLE|USER|TYPE|FUNCTION|TRIGGER|POLICY|SEQUENCE|COLLECTION)|TRUNCATE)\b/i.test(cmd)) return high("destructive DDL (DROP or TRUNCATE)");
  if (/\bDELETE\s+FROM\s+\S+/i.test(cmd) && !realWhere) return high("DELETE without a real WHERE wipes the whole table");
  if (/\bUPDATE\s+\S+\s+SET\b/i.test(cmd) && !realWhere) return high("UPDATE without a real WHERE rewrites the whole table");
  if (/\bALTER\s+TABLE\b[^;]*\bDROP\b/i.test(cmd)) return high("ALTER TABLE ... DROP removes a column or constraint");
  if (/\bFLUSH(ALL|DB)\b/i.test(cmd)) return high("redis FLUSH wipes the keyspace");
  if (/\b(alembic\s+downgrade|prisma\s+migrate\s+reset|prisma\s+db\s+push\b[^;&|]*(--force-reset|--accept-data-loss)|supabase\s+db\s+(reset|push)|dbmate\s+(drop|down)|rails\s+db:(drop|reset|schema:load)|manage\.py\s+(flush|sqlflush|migrate\s+\S+\s+zero)|flask\s+db\s+downgrade|goose\s+(down|reset)|migrate\b[^;&|]*\s(down|drop|force)\b)/i.test(cmd)) return high("schema-destructive migration command");
  return null;
}

function bypassRule(cmd) {
  if (/\bALLOW_MAIN=1\b/.test(cmd)) return hit("high", "ALLOW_MAIN=1 bypasses the main-branch guard (main is the release path)");
  if (/\bHUSKY=0\b/.test(cmd) || (/\bSKIP=\S+/.test(cmd) && /\b(git\s+commit|pre-commit)\b/.test(cmd))) return hit("caution", "bypasses commit hooks");
  if (/--dangerously-skip-permissions|--allow-dangerous|--no-sandbox|--unsafe-perm|--no-verify-ssl|--insecure(\s|$)|\s-k\s+https?:\/\//.test(cmd)) return hit("caution", "disables a safety check");
  return null;
}

const SEGMENT_RULES = [
  ["rm", rmRule],
  ["find", findRule],
  ["kill", killRule],
  ["system", systemRule],
  ["git", gitRule],
  ["docker", dockerRule],
  ["infra", infraRule],
  ["deploy", deployRule],
  ["transfer", transferRule],
  ["http", httpRule],
  ["bulk-edit", sedRule],
  ["money", moneyRule],
  ["prod-run", prodRunRule],
  ["inline", inlineScriptRule],
];

const COMMAND_RULES = [
  ["remote", remoteRule],
  ["sql", sqlRule],
  ["bypass", bypassRule],
];

function stripFileHeredocs(cmd) {
  const lines = cmd.split("\n");
  const kept = [];
  const writtenPaths = [];
  const writtenBodies = {};
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const opener = line.match(/<<-?\s*(['"]?)([A-Za-z_][\w-]*)\1/);
    if (!opener) {
      kept.push(line);
      continue;
    }
    const before = line.slice(0, opener.index);
    const after = line.slice(opener.index + opener[0].length);
    const redirect = (before + " " + after).match(/(?:^|\s)>{1,2}\s*(\S+)/);
    const teeTarget = before.match(/\btee\b\s+(?:-a\s+)?(\S+)/);
    if (!/\b(cat|tee)\b/.test(before) || !(redirect || teeTarget)) {
      kept.push(line);
      continue;
    }
    const target = stripQuotes((redirect && redirect[1]) || (teeTarget && teeTarget[1]));
    writtenPaths.push(target);
    kept.push((before + " <<" + opener[2] + " [file body scanned separately] " + after).replace(/\s+/g, " ").trim());
    const bodyLines = [];
    let j = i + 1;
    while (j < lines.length && lines[j].trim() !== opener[2]) bodyLines.push(lines[j++]);
    writtenBodies[target.split("/").pop()] = bodyLines.join("\n");
    i = j;
  }
  return { text: kept.join("\n"), writtenPaths, writtenBodies };
}

function writtenScriptRun(text, writtenPaths, writtenBodies, cwd) {
  if (!writtenPaths.length) return null;
  const names = new Set(writtenPaths.map((p) => p.split("/").pop()));
  const baseName = (a) => stripQuotes(a).split("/").pop();
  for (const segment of splitSegments(text)) {
    const tokens = leadTokens(segment);
    if (!tokens.length) continue;
    const runArg = (RUNNER_LEAD.test(tokens[0]) || tokens[0] === "source" || tokens[0] === ".") ? tokens.slice(1).find((a) => names.has(baseName(a))) : null;
    const execArg = /^\.\//.test(tokens.leadRaw || "") && names.has(baseName(tokens.leadRaw)) ? tokens.leadRaw : null;
    const name = runArg || execArg;
    if (!name) continue;
    const body = writtenBodies[baseName(name)];
    if (body === undefined) return { id: "written-script", tier: "caution", reason: "runs a script written in this same command; its body could not be read" };
    const inner = safely(scriptBodyRule, body, "written script") || safely(evaluateText, body, cwd, 1);
    if (!inner) continue;
    return { id: "written-script", tier: inner.tier, reason: "runs a script written in this same command: " + inner.reason };
  }
  return null;
}

function safely(rule, ...args) {
  try {
    return rule(...args);
  } catch {
    return null;
  }
}

function evaluateText(text, cwd, depth) {
  let best = null;
  const consider = (id, result) => {
    if (result && (!best || TIER_RANK[result.tier] > TIER_RANK[best.tier])) best = { id, tier: result.tier, reason: result.reason };
  };
  for (const [id, rule] of COMMAND_RULES) consider(id, safely(rule, text));
  let dir = cwd;
  for (const segment of splitSegments(text)) {
    const tokens = leadTokens(segment);
    if (!tokens.length) continue;
    if (tokens[0] === "cd" && tokens[1]) dir = resolveDir(dir, stripQuotes(tokens[1]));
    for (const [id, rule] of SEGMENT_RULES) consider(id, safely(rule, tokens, id === "git" ? dir : segment, dir));
    if (depth < MAX_NESTING) {
      for (const inner of safely(nestedTexts, tokens, segment) || []) {
        const nested = evaluateText(inner, dir, depth + 1);
        if (nested) consider(nested.id, nested);
      }
    }
  }
  return best;
}

function evaluate(cmd, cwd) {
  const { text, writtenPaths, writtenBodies } = stripFileHeredocs(cmd);
  let best = evaluateText(text, cwd, 0);
  if (!best) best = safely(writtenScriptRun, text, writtenPaths, writtenBodies, cwd);
  if (best && best.tier !== "high" && ENV_SENSITIVE_RULES.has(best.id) && PROD_MARKERS.test(text)) {
    best = { id: best.id, tier: "high", reason: best.reason + ", on a prod or staging target" };
  }
  return { best, text };
}

function ackTier(text) {
  const leading = text.match(ACK_LEADING);
  if (leading) return leading[1];
  const trailing = text.trimEnd().match(ACK_TRAILING);
  return trailing ? trailing[1] : null;
}

function flagInstructions(tier) {
  if (tier === "high") return "Flag it FIRST with the HIGH RISK block (🟥 **HIGH RISK** line + ```diff with '- ' lines: risk / blast / undo / gate). gate defaults to 'waiting for your OK': re-run with RISK_ACK=high as the leading assignment ONLY if the user explicitly asked for exactly this step; otherwise stop here.";
  if (tier === "warn") return "Flag it FIRST with the WARNING block (🟧 **WARNING** line + ```diff with '! ' lines: cost / cap / gate), then re-run with RISK_ACK=warn as the leading assignment. If the cost is unbounded or unknown, gate is 'waiting for your OK': stop here. After it runs, report 🟧 spent: <amount>.";
  return "Flag it FIRST on one line (🟨 **CAUTION** <what and why> · undo: <rollback>), then re-run with RISK_ACK=caution as the leading assignment. If it is outward-facing (merge, post, message) and the user did not ask for exactly this, gate is 'waiting for your OK': stop here.";
}

function deny(found) {
  const label = TIER_EMOJI[found.tier] + " risk-flag " + TIER_LABEL[found.tier] + " [" + found.id + "]: " + found.reason + ". ";
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: label + flagInstructions(found.tier) + " (A trailing '# RISK_ACK=<tier>' comment also works.)",
      },
    })
  );
}

function denyMismatch(found, ackedTier) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason:
          TIER_EMOJI[found.tier] + " risk-flag: this command is " + TIER_LABEL[found.tier] + " [" + found.id + "] (" + found.reason + ") but was acked as " + ackedTier + ". Re-flag at " + TIER_LABEL[found.tier] + " and re-run with RISK_ACK=" + found.tier + (found.tier === "high" ? ", only if the user explicitly asked for exactly this step." : "."),
      },
    })
  );
}

function acknowledged(found) {
  process.stdout.write(JSON.stringify({ systemMessage: TIER_EMOJI[found.tier] + " " + TIER_LABEL[found.tier] + " acknowledged [" + found.id + "]: " + found.reason }));
}

function main(raw) {
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    return;
  }
  const event = payload.hook_event_name || (payload.prompt !== undefined ? "UserPromptSubmit" : "PreToolUse");
  if (event === "UserPromptSubmit") {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext: RULE_TEXT } }));
    return;
  }
  if (event !== "PreToolUse") return;
  if (payload.tool_name && payload.tool_name !== "Bash") return;
  const cmd = payload.tool_input && payload.tool_input.command;
  if (!cmd || typeof cmd !== "string") return;
  const { best, text } = evaluate(cmd, payload.cwd);
  if (!best) return;
  const acked = ackTier(text);
  if (!acked) return deny(best);
  if (TIER_RANK[acked] < TIER_RANK[best.tier]) return denyMismatch(best, acked);
  acknowledged(best);
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  try {
    main(input);
  } catch {
    process.exit(0);
  }
});
