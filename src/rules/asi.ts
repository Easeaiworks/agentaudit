/**
 * OWASP Top 10 for Agentic Applications (2026) -- ASI01 through ASI10.
 *
 * Published 2025-12-09 by the OWASP GenAI Security Project.
 * https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
 *
 * Detection philosophy
 * --------------------
 * Agentic risk is overwhelmingly about *missing controls*, not about the
 * presence of a forbidden token. A codebase is not insecure because it calls
 * `exec` -- it is insecure because it calls `exec` with a string that an LLM
 * influenced, inside a process that has no sandbox and no egress policy.
 *
 * So each rule below combines:
 *   - `presence` probes for genuinely dangerous constructs, and
 *   - `control` probes that fire only when the project clearly performs the
 *     risky behaviour AND shows no evidence of the mitigating control.
 *
 * The control probes are deliberately generous in what counts as evidence:
 * a false negative (staying quiet because you probably handled it) is far
 * less costly to a paying user than a wall of false positives.
 */

import type { Rule } from "../types.js";

// Shared fragments -----------------------------------------------------------

/** Evidence that the project defines or dispatches agent tools at all. */
const TOOL_SURFACE =
  /\b(tools\s*[:=]\s*\[|tool_choice|function_call|toolCalls?|tool_use|registerTool|defineTool|@tool\b|StructuredTool|DynamicTool|FunctionDeclaration|AddFunction|ChatCompletionsFunctionTool)/;

/** Evidence that the project talks to a model provider. */
const MODEL_CALL =
  /\b(openai|anthropic|OpenAI|Anthropic|chat\.completions|messages\.create|generateText|streamText|invoke_model|InvokeModel|ChatCompletion|generateContent)\b/;

/** Evidence that retrieved / external content flows somewhere. */
const RETRIEVAL_SURFACE =
  /\b(vectorStore|vectorstore|pinecone|Pinecone|weaviate|qdrant|Qdrant|chroma|Chroma|similaritySearch|retriever|Retriever|embeddings?\.|pgvector|RAG)\b/;

export const ASI_RULES: Rule[] = [
  // ASI01 --------------------------------------------------------------------
  {
    id: "ASI01",
    framework: "OWASP-ASI-2026",
    title: "Agent Goal Hijack",
    severity: "critical",
    description:
      "An attacker redirects the agent's objective using content the agent reads " +
      "(a web page, a document, a tool result, an email). Because retrieved text is " +
      "concatenated into the same context window as the operator's instructions, the " +
      "model cannot reliably tell data from directives.",
    remediation:
      "Structurally separate retrieved content from instructions: place untrusted text " +
      "in a dedicated, clearly delimited message or field and instruct the model that it " +
      "is data, never commands. Re-assert the system objective after any tool result. " +
      "Constrain the agent to an explicit allowlist of goals and require human confirmation " +
      "before the objective changes.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "presence",
        // Covers JS template literals, Python f-strings, C# interpolated
        // strings ($"..{x}.."), Go/Java/C# concatenation, and := assignment.
        match:
          /(?:system|systemPrompt|instructions|system_prompt)\s*(?::=|[:=])\s*(?:[a-z]?`[^`]*\$?\{|[fF]?\$?['"][^'"]*['"]\s*\+|[fF]['"][^'"]*\{|\$['"][^'"]*\{)/,
        message:
          "Untrusted or dynamic content is interpolated directly into the system prompt. " +
          "Anything reachable by an attacker in that string becomes an instruction.",
      },
      {
        kind: "presence",
        match:
          /\b(?:content|text|body|pageContent|document)\s*[:=]\s*(?:await\s+)?(?:fetch|axios|request|scrape|crawl|readFile)\b[\s\S]{0,120}?\b(?:messages|prompt)\b/,
        message:
          "Fetched external content appears to flow into the prompt without an intervening " +
          "sanitisation or delimiting step.",
      },
      {
        kind: "control",
        trigger: RETRIEVAL_SURFACE,
        control:
          /\b(untrusted|sanitiz|sanitis|delimit|escapeBraces|stripInstructions|promptInjection|injection[_-]?guard|spotlight|datamark|<untrusted|UNTRUSTED_)/i,
        message:
          "The project retrieves external content into model context but shows no evidence " +
          "of delimiting or marking it as untrusted data (ASI01 primary mitigation).",
      },
    ],
  },

  // ASI02 --------------------------------------------------------------------
  {
    id: "ASI02",
    framework: "OWASP-ASI-2026",
    title: "Tool Misuse & Exploitation",
    severity: "critical",
    description:
      "Legitimate tools are bent toward illegitimate outcomes via deceptive input or " +
      "poisoned tool metadata. A tool that is safe in isolation becomes an attack " +
      "primitive when its parameters are model-controlled and unvalidated.",
    remediation:
      "Scope every tool to least privilege. Validate tool parameters against a strict " +
      "schema server-side -- never trust the model to produce well-formed arguments. " +
      "Apply runtime policy checks before execution, and treat tool descriptions from " +
      "third-party servers as untrusted input.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "control",
        trigger: TOOL_SURFACE,
        control:
          /\b(zod|z\.object|joi|yup|ajv|JSONSchema|json_schema|parameters\s*:\s*\{[\s\S]{0,80}required|pydantic|BaseModel|validateArgs|parseArgs)\b/,
        message:
          "Tools are defined but no parameter schema validation is evident. Model-produced " +
          "arguments should be validated server-side before execution.",
      },
      {
        kind: "control",
        trigger: TOOL_SURFACE,
        control:
          /\b(allowlist|allowList|whitelist|permittedTools|allowedTools|toolPolicy|canUseTool|authorizeTool|scopes?\s*:)/i,
        message:
          "No tool allowlist or per-invocation authorisation policy detected. Agents should " +
          "hold the minimum tool set required for the current task.",
      },
    ],
  },

  // ASI03 --------------------------------------------------------------------
  {
    id: "ASI03",
    framework: "OWASP-ASI-2026",
    title: "Identity & Privilege Abuse",
    severity: "critical",
    description:
      "Agents borrow human credentials or run on long-lived tokens. When such an agent " +
      "is hijacked, the attacker inherits every permission the token carries, and the " +
      "audit trail attributes the actions to a human.",
    remediation:
      "Give each agent its own identity distinct from any user. Issue short-lived, " +
      "narrowly scoped credentials with automatic expiration; exchange them per task " +
      "rather than holding a standing token. Never let an agent operate under a human's " +
      "session credentials.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "presence",
        match:
          /(?:api[_-]?key|secret|token|password|passwd|credential)\s*[:=]\s*['"`][A-Za-z0-9_\-]{16,}['"`]/i,
        // Placeholder credentials are the dominant false positive on real
        // repositories -- docs, examples, and constructor defaults are full of
        // them. `phc_` is PostHog's project key, which is public by design.
        unless:
          /(?:process\.env|import\.meta\.env|getenv|Deno\.env|os\.environ|System\.getenv|example|placeholder|xxx+|your[_-]?\w+|[_-]here\b|change[_-]?me|dummy|fake|sample|redacted|insert[_-]|add[_-]your|replace[_-]|<[a-z]|\.\.\.|phc_|pk_test|sk_test|\bTODO\b)/i,
        message:
          "Hardcoded long-lived credential. Agent credentials must be short-lived, scoped, " +
          "and injected at runtime.",
      },
      {
        kind: "presence",
        match: /\b(?:expiresIn|expires_in|ttl|maxAge)\s*[:=]\s*['"`]?(?:0|never|none|Infinity)\b/i,
        message: "A credential or session is configured to never expire.",
      },
      {
        kind: "control",
        trigger: TOOL_SURFACE,
        control:
          /\b(assumeRole|AssumeRole|STS|getServiceAccount|serviceAccount|workload[_-]?identity|expiresIn|expires_at|short[_-]?lived|refreshToken|rotateCredential|OAuth2|client_credentials)\b/i,
        message:
          "Agent performs tool calls but no scoped or short-lived credential exchange is " +
          "evident -- the agent may be running on a standing token.",
      },
    ],
  },

  // ASI04 --------------------------------------------------------------------
  {
    id: "ASI04",
    framework: "OWASP-ASI-2026",
    title: "Agentic Supply Chain Vulnerabilities",
    severity: "high",
    description:
      "Compromised frameworks, MCP servers, model artifacts, or plugins propagate " +
      "through every deployment that trusts them. Agentic stacks pull in a long tail of " +
      "fast-moving dependencies, and MCP servers execute with the agent's privileges.",
    remediation:
      "Maintain an AIBOM covering models, prompts, tools, and MCP servers. Pin exact " +
      "versions and commit a lockfile. Require signed releases and verified provenance " +
      "for MCP servers. Run SCA policy checks before deployment, not after.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "presence",
        match: /"(?:[@\w\/\-\.]+)"\s*:\s*"(?:\*|latest|>=?\s*[\d])/,
        // `engines` declares the runtime floor, not a dependency -- a caret
        // there is correct, not a supply-chain risk.
        unless: /"(?:node|npm|yarn|pnpm|bun|vscode|deno|python)"\s*:/,
        files: /package\.json$/,
        message:
          "Unpinned dependency range. Agentic dependencies should be pinned to exact " +
          "versions with a committed lockfile.",
      },
      {
        kind: "presence",
        match: /\b(?:npx|uvx|pipx run)\s+(?:-y\s+)?(?!--)[a-z@][\w@\/\-\.]*(?!.*@\d)/,
        files: /(?:mcp[_-]?config|claude_desktop_config|\.mcp\.json|mcp\.json|Dockerfile|\.sh)$/i,
        message:
          "MCP server or tool launched at an unpinned version. A compromised upstream " +
          "release executes immediately with agent privileges.",
      },
      {
        kind: "control",
        trigger: /\b(mcpServers|modelcontextprotocol|MCPServer|StdioServerTransport)\b/,
        control: /\b(AIBOM|aibom|sbom|SBOM|provenance|cosign|sigstore|integrity|subresource|npm\s+audit|pip-audit|snyk|dependabot)\b/i,
        message:
          "MCP servers are configured but no SBOM/AIBOM, provenance verification, or " +
          "dependency scanning is evident.",
      },
    ],
  },

  // ASI05 --------------------------------------------------------------------
  {
    id: "ASI05",
    framework: "OWASP-ASI-2026",
    title: "Unexpected Code Execution (RCE)",
    severity: "critical",
    description:
      "Natural language is converted into running code outside its intended boundary. " +
      "Code-interpreter tools, dynamic evaluation, and shell tools let a hijacked agent " +
      "execute arbitrary commands on the host.",
    remediation:
      "Execute all model-authored code in a containerised sandbox with deny-by-default " +
      "network egress, a read-only root filesystem, and a hard timeout. Prefer " +
      "parameterised APIs over raw shell. Never pass model output to eval, exec, or a " +
      "shell string.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "presence",
        // `Function(` must be `new Function(` -- bare Function(...) is an
        // ordinary constructor in most languages (e.g. openai-python's
        // Function(name=..., arguments=...) tool-call type).
        // `exec` must not be a method call: `re.exec(text)` is
        // RegExp.prototype.exec, not process execution. Only bare exec(...)
        // and Python's exec() are code execution.
        match:
          /(?<![.\w])(?:eval|new\s+Function|exec)\s*\(\s*(?!['"`]|\s*\))(?:[a-zA-Z_$][\w$]*\s*[,)+.]|`)/,
        unless: /\/\/\s*agentaudit-ignore|#\s*agentaudit-ignore/,
        message:
          "Dynamic evaluation of a non-literal value. If any part of this derives from " +
          "model output, it is direct RCE.",
      },
      {
        kind: "presence",
        // Three shapes: template literal with ${...}, quoted string with +
        // concatenation, and Python f-string / %-format passed to a shell.
        // JS/TS, Python, Go (exec.Command), C#/Java (Process.Start,
        // Runtime.getRuntime().exec), PHP (shell_exec).
        match:
          /\b(?:exec|execSync|spawn|spawnSync|execFile|system|popen|subprocess\.(?:run|call|Popen)|os\.system|shell_exec|exec\.Command|exec\.CommandContext|Process\.Start|ProcessBuilder|Runtime\.getRuntime\(\)\.exec)\s*\(\s*(?:[^)]*,\s*)*?(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[fF]['"][^'"]*\{|\$['"][^'"]*\{|[a-zA-Z_$][\w$.]*\s*\+)/,
        message:
          "Shell command built by string interpolation or concatenation. Model-influenced " +
          "values in a shell string are a command-injection primitive.",
      },
      {
        kind: "control",
        trigger:
          /\b(?:code_interpreter|codeInterpreter|runPython|executeCode|pythonRepl|PythonREPL|shell_tool|bashTool|BashTool|run_command)\b/,
        control:
          /\b(docker|container|firecracker|gvisor|nsjail|seccomp|--network[= ]none|readOnlyRootFilesystem|vm2|isolated-vm|isolatedVm|pyodide|wasm|sandbox)\b/i,
        message:
          "A code-execution tool is exposed to the agent with no evidence of sandboxing or " +
          "network egress restriction.",
      },
    ],
  },

  // ASI06 --------------------------------------------------------------------
  {
    id: "ASI06",
    framework: "OWASP-ASI-2026",
    title: "Memory & Context Poisoning",
    severity: "high",
    description:
      "Malicious content planted in session context or long-term memory shapes all " +
      "future behaviour. Unlike a single hijacked turn, a poisoned memory persists and " +
      "re-attacks the agent on every subsequent run, often across users.",
    remediation:
      "Validate and attribute every memory write -- record who wrote it and from what " +
      "source. Scope memory per user and per task; never share a global memory across " +
      "tenants. Keep context ephemeral by default, expire aggressively, and make stored " +
      "memory inspectable and revocable by the operator.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "control",
        trigger:
          /\b(?:memory|Memory|conversationHistory|chatHistory|BufferMemory|VectorStoreRetrieverMemory|saveContext|addMemory|remember|persistMessage)\b/,
        control:
          /\b(?:userId|user_id|tenantId|tenant_id|sessionId|session_id|namespace|scope|partitionKey)\b/,
        message:
          "Agent memory is persisted without an evident per-user or per-tenant scope key. " +
          "Cross-tenant memory bleed is both a poisoning and a disclosure vector.",
      },
      {
        kind: "control",
        trigger: /\b(?:saveContext|addMemory|upsertMemory|persistMessage|memory\.(?:add|save|write))\b/,
        control: /\b(?:validate|sanitiz|sanitis|schema\.parse|zod|ttl|expiresAt|expires_at|maxAge|prune|evict)\b/i,
        message:
          "Memory writes show no validation or expiry. Poisoned entries persist " +
          "indefinitely and influence every later run.",
      },
    ],
  },

  // ASI07 --------------------------------------------------------------------
  {
    id: "ASI07",
    framework: "OWASP-ASI-2026",
    title: "Insecure Inter-Agent Communication",
    severity: "high",
    description:
      "Unauthenticated agent-to-agent channels let an attacker impersonate an agent, " +
      "tamper with messages in flight, or replay a previously trusted delegation.",
    remediation:
      "Require mutual authentication between agents (mTLS or signed tokens). Sign and " +
      "integrity-protect every message, including a nonce and timestamp to defeat replay. " +
      "Maintain an explicit delegation allowlist describing which agent may instruct which.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "presence",
        // Must look like a real host (dot or port), not a bare scheme token.
        match: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[a-z0-9][a-z0-9.-]*[.:][a-z0-9]/i,
        // Scheme-validation code (`url.startswith(('http://', 'https://'))`) is
        // a security control, not a vulnerability. Any line that also mentions
        // https:// or a scheme check is almost certainly parsing, not calling.
        unless:
          /https:\/\/|startswith|startsWith|\bscheme\b|\bprotocol\b|\bproxy\b|hasScheme|urlparse|urlsplit|\.split\(|\.replace\(|regex|pattern|e\.g\.|example|allowlist|whitelist/i,
        message:
          "Plaintext HTTP endpoint. Inter-agent traffic must be encrypted and mutually " +
          "authenticated.",
      },
      {
        kind: "control",
        trigger:
          /\b(?:agentToAgent|a2a|A2A|handoff|handoffs|delegateTo|subAgent|subagent|crewai|CrewAI|autogen|AutoGen|swarm|Swarm)\b/,
        control:
          /\b(?:mtls|mTLS|clientCertificate|signMessage|verifySignature|hmac|HMAC|jwt|JWT|nonce|Authorization\s*:|bearer)\b/i,
        message:
          "Multi-agent handoff detected with no evident authentication or message signing " +
          "between agents.",
      },
    ],
  },

  // ASI08 --------------------------------------------------------------------
  {
    id: "ASI08",
    framework: "OWASP-ASI-2026",
    title: "Cascading Failures",
    severity: "high",
    description:
      "One agent's error propagates through connected workflows. Without isolation, a " +
      "single hijack or malformed output compromises every downstream system, and " +
      "retry loops amplify the blast radius rather than containing it.",
    remediation:
      "Isolate blast radius: separate environments and credentials per agent. Add circuit " +
      "breakers that trip on behavioural deviation, not just on HTTP errors. Bound retries " +
      "and total steps. Fail closed -- an agent that cannot verify its state should stop, " +
      "not proceed.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "control",
        trigger: /\b(?:while\s*\(\s*true|for\s*\(\s*;;|agentLoop|runAgent|executeAgent|\.invoke\(|AgentExecutor)\b/,
        control:
          /\b(?:maxIterations|max_iterations|maxSteps|max_steps|maxTurns|max_turns|maxRetries|max_retries|circuitBreaker|breaker|bulkhead|AbortSignal|timeout)\b/i,
        message:
          "Agent execution loop with no evident iteration cap, retry bound, or timeout. " +
          "An agent that cannot terminate cannot be contained.",
      },
      {
        kind: "control",
        trigger: TOOL_SURFACE,
        control: /\b(?:try\s*\{|catch\s*\(|except\b|Result<|\.catch\()/,
        message:
          "Tool dispatch without evident error handling -- failures will propagate " +
          "uncontained to callers.",
      },
    ],
  },

  // ASI09 --------------------------------------------------------------------
  {
    id: "ASI09",
    framework: "OWASP-ASI-2026",
    title: "Human-Agent Trust Exploitation",
    severity: "high",
    description:
      "The agent manipulates approval by controlling what the human sees at the moment " +
      "of confirmation. A summary that says 'archive 3 old files' can accompany a call " +
      "that deletes a bucket. Approval UX built from model-generated prose is a " +
      "confused-deputy channel.",
    remediation:
      "Show the raw, resolved action -- exact command, exact target, exact scope -- not a " +
      "model-written summary of it. Keep immutable logs of what was displayed alongside " +
      "what was executed, so divergence is detectable after the fact. Forbid persuasive " +
      "or urgency framing in confirmation copy. Require re-authentication for " +
      "irreversible actions.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "presence",
        // "yolo" alone matches the YOLO object-detection model in any ML
        // codebase; require it to look like an actual flag.
        match:
          /\b(?:autoApprove|auto_approve|autoConfirm|skipConfirmation|skip_confirmation|bypassApproval|bypass_approval|yolo[_-]?mode|yoloMode|--yolo\b|dangerouslySkip|--yes\b|force\s*:\s*true)\b/i,
        message:
          "Approval gate is bypassed. Irreversible agent actions require explicit human " +
          "confirmation of the resolved action.",
      },
      {
        kind: "control",
        trigger:
          /\b(?:delete|drop|remove|destroy|terminate|transfer|payment|charge|refund|deploy|merge|force[_-]?push)\w*\s*\(/i,
        control:
          /\b(?:confirm|approval|approve|requireHuman|humanInTheLoop|human_in_the_loop|interrupt|checkpoint|reAuth|reauthenticate|mfa|MFA)\b/i,
        message:
          "Irreversible or high-impact operations are reachable with no evident " +
          "human-in-the-loop confirmation step.",
      },
    ],
  },

  // ASI10 --------------------------------------------------------------------
  {
    id: "ASI10",
    framework: "OWASP-ASI-2026",
    title: "Rogue Agents",
    severity: "critical",
    description:
      "An agent operates outside policy while appearing legitimate -- continuing to run " +
      "after its task ends, pursuing objectives no one assigned, or persisting through " +
      "restarts. Without behavioural baselines there is nothing to compare against, and " +
      "without a kill switch there is no way to stop it.",
    remediation:
      "Establish behavioural baselines and alert on deviation (unusual tool mix, unusual " +
      "volume, off-hours activity). Govern agent lifecycle explicitly: registration, " +
      "expiry, deregistration. Implement and regularly test a kill switch that revokes " +
      "credentials and halts execution. Log every action to an append-only store.",
    references: [
      "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    ],
    probes: [
      {
        kind: "control",
        trigger: TOOL_SURFACE,
        control:
          /\b(?:auditLog|audit_log|auditTrail|structuredLog|logger\.(?:info|warn|audit)|winston|pino|serilog|Serilog|OpenTelemetry|opentelemetry|trace\.|span)\b/i,
        message:
          "Agent actions are dispatched with no evident audit logging. Rogue behaviour is " +
          "undetectable and unforensicable without an action log.",
      },
      {
        kind: "control",
        trigger: /\b(?:agentLoop|runAgent|AgentExecutor|executeAgent|\.invoke\(|startAgent)\b/,
        control:
          /\b(?:killSwitch|kill_switch|shutdown|abortController|AbortController|AbortSignal|cancellationToken|CancellationToken|SIGTERM|terminate\()/,
        message:
          "No kill switch or cancellation path is evident for running agents. Containment " +
          "requires the ability to halt an agent mid-execution.",
      },
    ],
  },
];
