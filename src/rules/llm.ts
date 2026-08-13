/**
 * OWASP Top 10 for LLM Applications (2025) -- the subset that is statically
 * detectable and that materially overlaps agentic deployments.
 *
 * https://genai.owasp.org/llm-top-10/
 *
 * Rules that cannot be meaningfully assessed from source alone (LLM04 Data and
 * Model Poisoning, LLM09 Misinformation) are covered in the manual review
 * checklist under templates/ rather than being faked here with regexes.
 */

import type { Rule } from "../types.js";

export const LLM_RULES: Rule[] = [
  {
    id: "LLM01",
    framework: "OWASP-LLM-2025",
    title: "Prompt Injection",
    severity: "critical",
    description:
      "User or retrieved input alters the model's behaviour in ways the operator did " +
      "not intend. Direct injection comes from the user; indirect injection arrives " +
      "through content the model reads.",
    remediation:
      "Treat all model input as untrusted. Delimit and label external content, constrain " +
      "output format, and enforce privilege boundaries outside the model -- the model is " +
      "not a security control. Validate that outputs conform to expectations before acting.",
    references: ["https://genai.owasp.org/llm-top-10/"],
    probes: [
      {
        kind: "presence",
        match: /\b(?:role\s*:\s*['"]system['"][\s\S]{0,200}?\$\{(?:req|request|input|userInput|query|params|body)\b)/,
        message:
          "Request-derived data is interpolated into a system message -- direct prompt " +
          "injection into the highest-trust channel.",
      },
      {
        kind: "control",
        trigger: /\b(?:chat\.completions|messages\.create|generateText|streamText|generateContent|ChatCompletion)\b/,
        // Delimiting untrusted content is the primary mitigation and counts as
        // evidence here, matching how ASI01 treats it. A guardrail library is
        // sufficient but not necessary.
        control:
          /\b(?:guardrail|Guardrail|moderation|moderations\.create|llamaGuard|LlamaGuard|promptShield|nemoguardrails|rebuff|sanitizeInput|inputFilter|untrusted|UNTRUSTED_|delimit|spotlight|datamark|promptInjection)\b|<untrusted/i,
        message:
          "Model is invoked with no evident input guardrail, moderation, injection filter, " +
          "or delimiting of untrusted content.",
      },
    ],
  },
  {
    id: "LLM02",
    framework: "OWASP-LLM-2025",
    title: "Sensitive Information Disclosure",
    severity: "high",
    description:
      "PII, credentials, or proprietary data leak through model output, logged prompts, " +
      "or third-party provider retention. Agents widen this surface because they read " +
      "from internal systems and write to external ones.",
    remediation:
      "Redact PII and secrets before they enter the context window and before prompts are " +
      "logged. Apply output filtering for sensitive patterns. Confirm provider data " +
      "retention and opt out of training use. Enforce per-user data scoping on retrieval.",
    references: ["https://genai.owasp.org/llm-top-10/"],
    probes: [
      {
        kind: "presence",
        // The sensitive term must appear as an *expression* -- directly after
        // `(`, `,`, `{`, or `$`, and followed by expression punctuation. Without
        // this, every `logger.info('using access token')` fires: the word is
        // prose inside a string literal, not a value being logged.
        match:
          /\b(?:console\.log|logger\.(?:info|debug|log|warn)|print)\s*\((?:[^)]*?[(,{$]\s*)?(?:prompt|messages|systemPrompt|system_prompt|apiKey|api_key|token|secret)\s*[,)\.\[\}]/,
        unless: /\bredact|mask|scrub|len\(|\.length|count|n_tokens|num_tokens|token_count/i,
        message:
          "Full prompt or credential material written to logs without redaction.",
      },
      {
        kind: "control",
        trigger: /\b(?:ssn|socialSecurity|creditCard|credit_card|dateOfBirth|date_of_birth|passport|medicalRecord|patient|diagnosis)\b/i,
        control: /\b(?:redact|mask|scrub|anonymiz|anonymis|pseudonymiz|tokeniz|presidio|Presidio|deidentif)/i,
        message:
          "Sensitive personal data categories appear in a codebase that sends data to a " +
          "model, with no evident redaction or de-identification step.",
      },
    ],
  },
  {
    id: "LLM05",
    framework: "OWASP-LLM-2025",
    title: "Improper Output Handling",
    severity: "high",
    description:
      "Model output is passed to a downstream consumer without validation. LLM output " +
      "reaching a template, a DOM, a database driver, or a shell is indistinguishable " +
      "from attacker-controlled input.",
    remediation:
      "Treat every model output as untrusted user input. Encode contextually before " +
      "rendering, use parameterised queries, and validate against a schema before acting " +
      "on structured output.",
    references: ["https://genai.owasp.org/llm-top-10/"],
    probes: [
      {
        kind: "presence",
        match:
          /\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|v-html|insertAdjacentHTML)\b[\s\S]{0,80}?\b(?:completion|response|message|content|output|result|answer|llm|aiResponse)\b/i,
        message:
          "Model output rendered as raw HTML. This is a direct XSS sink.",
      },
      {
        kind: "presence",
        match:
          /\b(?:query|execute|raw)\s*\(\s*[`'"][^`'"]*\$\{[^}]*\b(?:completion|response|content|output|answer|llmResult)\b/i,
        message:
          "Model output interpolated into a SQL string. Use parameterised queries.",
      },
      {
        kind: "control",
        trigger: /\b(?:JSON\.parse)\s*\(\s*(?:completion|response|content|message|output|result|text)\b/i,
        control: /\b(?:zod|z\.object|safeParse|ajv|validate|schema\.parse|pydantic|try\s*\{)/,
        message:
          "Structured model output is parsed without schema validation or error handling.",
      },
    ],
  },
  {
    id: "LLM06",
    framework: "OWASP-LLM-2025",
    title: "Excessive Agency",
    severity: "critical",
    description:
      "The system grants the model more functionality, permission, or autonomy than the " +
      "use case requires. Excessive agency is what converts a prompt injection into a " +
      "material breach.",
    remediation:
      "Minimise extensions, functionality, and permissions. Prefer narrowly-scoped tools " +
      "over general ones (a `sendEmailToSelf` tool over a general `sendEmail`). Require " +
      "human approval for high-impact actions and enforce permissions in the downstream " +
      "system, not in the prompt.",
    references: ["https://genai.owasp.org/llm-top-10/"],
    probes: [
      {
        kind: "presence",
        match:
          /\b(?:allowAllTools|allow_all|permissions?\s*[:=]\s*['"`]\*['"`]|scope\s*[:=]\s*['"`](?:\*|admin|root|full_access)['"`])/i,
        message: "Wildcard or administrative permission granted to an agent.",
      },
      {
        kind: "presence",
        match: /\b(?:GRANT ALL|role\s*[:=]\s*['"`](?:admin|superuser|owner)['"`]|service_role)\b/,
        message:
          "Agent operates with an administrative or service-role database identity. Use a " +
          "least-privilege role with row-level security.",
      },
    ],
  },
  {
    id: "LLM07",
    framework: "OWASP-LLM-2025",
    title: "System Prompt Leakage",
    severity: "medium",
    description:
      "System prompts are extracted by users. The real risk is not the prose -- it is " +
      "that teams place credentials, connection strings, internal endpoints, or " +
      "authorisation rules inside the system prompt and rely on it staying secret.",
    remediation:
      "Assume the system prompt is public. Never place secrets, keys, or authorisation " +
      "logic in it. Enforce access control in application code, independently of prompt " +
      "content.",
    references: ["https://genai.owasp.org/llm-top-10/"],
    probes: [
      {
        kind: "presence",
        match:
          /(?:system|systemPrompt|instructions)\s*[:=][\s\S]{0,300}?\b(?:api[_-]?key|password|secret|connection[_-]?string|bearer|internal\.[a-z]+\.com|localhost:\d{4})\b/i,
        message:
          "The system prompt appears to contain secrets, internal endpoints, or " +
          "credentials. Treat the system prompt as public.",
      },
    ],
  },
  {
    id: "LLM10",
    framework: "OWASP-LLM-2025",
    title: "Unbounded Consumption",
    severity: "medium",
    description:
      "Unrestricted inference lets an attacker drive cost, exhaust capacity, or run a " +
      "model-extraction campaign. Agentic loops multiply this: one request can fan out " +
      "into hundreds of model calls.",
    remediation:
      "Enforce per-user and per-key rate limits, cap max_tokens, set request timeouts, " +
      "bound agent iterations, and alert on spend anomalies. Apply quotas at the edge, " +
      "not only inside the agent loop.",
    references: ["https://genai.owasp.org/llm-top-10/"],
    probes: [
      {
        kind: "control",
        trigger: /\b(?:chat\.completions|messages\.create|generateText|generateContent|ChatCompletion)\b/,
        control: /\b(?:max_tokens|maxTokens|maxOutputTokens|max_output_tokens)\b/,
        message: "Model invoked with no output token cap.",
      },
      {
        kind: "control",
        trigger: /\b(?:chat\.completions|messages\.create|generateText|generateContent|ChatCompletion)\b/,
        control:
          /\b(?:rateLimit|rate_limit|rateLimiter|ratelimit|throttle|quota|bottleneck|upstash|limiter|slowDown)\b/i,
        message: "No rate limiting or quota evident around model invocation.",
      },
      {
        kind: "control",
        trigger: /\b(?:chat\.completions|messages\.create|generateText|generateContent)\b/,
        control: /\b(?:timeout|AbortSignal|abortSignal|signal\s*:|deadline)\b/i,
        message: "Model calls have no evident timeout or abort signal.",
      },
    ],
  },
];

/**
 * EU AI Act transparency obligations became enforceable 2026-08-02.
 * Watermarking of synthetic content was extended to 2026-12-02 by the
 * digital omnibus agreement.
 *
 * These are engineering-visible proxies only. They are not legal advice and
 * they do not establish conformity -- see templates/eu-ai-act-readiness.md
 * for the assessment that actually has to be performed by a human.
 */
export const EU_AI_ACT_RULES: Rule[] = [
  {
    id: "EUAIA-52",
    framework: "EU-AI-ACT",
    title: "Article 50 - Disclosure that the user is interacting with an AI system",
    severity: "high",
    description:
      "Providers must ensure natural persons are informed they are interacting with an " +
      "AI system, unless it is obvious from context. Enforceable since 2 August 2026.",
    remediation:
      "Render a persistent, non-dismissible disclosure in any user-facing conversational " +
      "surface. Record the disclosure text and its effective date in your technical " +
      "documentation.",
    references: [
      "https://artificialintelligenceact.eu/article/50/",
      "https://www.lw.com/en/insights/ai-act-update-eu-resolves-to-change-rules-and-extend-deadlines",
    ],
    probes: [
      {
        kind: "control",
        trigger: /\b(?:ChatWindow|ChatInterface|MessageList|Conversation|chatbot|ChatBot|assistantMessage)\b/,
        control:
          /\b(?:AI[- ]generated|AI disclosure|aiDisclosure|You are (?:chatting|speaking|interacting) with an AI|powered by AI|This is an AI|automated assistant)\b/i,
        message:
          "User-facing conversational UI with no evident AI-interaction disclosure " +
          "(EU AI Act Art. 50(1), enforceable 2026-08-02).",
      },
    ],
  },
  {
    id: "EUAIA-50",
    framework: "EU-AI-ACT",
    title: "Article 50 - Marking of synthetic content",
    severity: "medium",
    description:
      "Providers of systems generating synthetic audio, image, video, or text must mark " +
      "outputs in a machine-readable format as artificially generated. The compliance " +
      "date for this obligation was extended to 2 December 2026.",
    remediation:
      "Attach C2PA/Content Credentials manifests or equivalent machine-readable " +
      "provenance metadata to generated media. Document the marking method.",
    references: ["https://artificialintelligenceact.eu/article/50/"],
    probes: [
      {
        kind: "control",
        trigger:
          /\b(?:images\.generate|generateImage|dall-?e|DALL-?E|stable[_-]?diffusion|midjourney|text-to-image|generateSpeech|tts\.|synthesiz)\b/i,
        control: /\b(?:c2pa|C2PA|contentCredentials|content_credentials|watermark|provenance|synthid|SynthID|metadata\.ai)\b/i,
        message:
          "Synthetic media generation detected with no evident machine-readable marking " +
          "(EU AI Act Art. 50(2), compliance date 2026-12-02).",
      },
    ],
  },
];
