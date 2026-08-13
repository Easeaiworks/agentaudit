// Deliberately vulnerable agent used as a detection fixture.
// Every construct here maps to a specific ASI/LLM rule. Do not copy this.

import OpenAI from "openai";
import { exec } from "node:child_process";

const openai = new OpenAI({ apiKey: "sk-proj-abcd1234efgh5678ijkl9012mnop" }); // ASI03

const memory: Record<string, string[]> = {}; // ASI06: global, unscoped

export async function runAgent(userInput: string, retrievedDoc: string) {
  // ASI01 / LLM01: retrieved content spliced straight into the system prompt
  const systemPrompt = `You are an ops assistant. Context: ${retrievedDoc}
  Internal API key is sk-internal-9f8e7d6c5b4a3210 and the admin endpoint is
  http://internal.acme.com/admin`; // LLM07

  const messages = [
    { role: "system", content: systemPrompt },
    { role: "user", content: userInput },
  ];

  // LLM10: no max_tokens, no timeout, no rate limit
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: messages as any,
    tools: [
      {
        type: "function",
        function: {
          name: "run_command",
          description: "Run any shell command",
          parameters: { type: "object", properties: { cmd: { type: "string" } } },
        },
      },
    ],
  });

  console.log("prompt was", messages); // LLM02

  const call = completion.choices[0].message.tool_calls?.[0];
  if (call) {
    const args = JSON.parse(call.function.arguments); // LLM05: unvalidated
    // ASI05: shell string built from model output, no sandbox
    exec(`bash -c "${args.cmd}"`, (e, stdout) => {
      memory["global"] = [...(memory["global"] ?? []), stdout]; // ASI06
    });
  }

  return completion;
}

// ASI09: irreversible action with approval explicitly bypassed
export async function deleteBucket(name: string, autoApprove = true) {
  if (autoApprove) {
    await exec(`aws s3 rb s3://${name} --force`);
  }
}

// ASI08 / ASI10: unbounded loop, no kill switch, no audit log
export async function agentLoop(goal: string) {
  while (true) {
    const r = await runAgent(goal, await fetch("http://feeds.example.com/tasks").then((x) => x.text()));
    if (!r) break;
  }
}
