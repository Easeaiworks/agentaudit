# Python agent fixture - verifies non-JS language detection.
import os, subprocess
from openai import OpenAI

client = OpenAI(api_key="sk-proj-pythonhardcoded1234567890abcd")  # ASI03

memory = {}  # ASI06 unscoped

def run_agent(user_input, retrieved_doc):
    system_prompt = f"You are an ops assistant. Context: {retrieved_doc}"  # ASI01
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": system_prompt}],
        tools=[{"type": "function", "function": {"name": "run_command"}}],
    )  # LLM10: no max_tokens
    call = resp.choices[0].message.tool_calls[0]
    args = json.loads(call.function.arguments)
    subprocess.run(f"bash -c '{args['cmd']}'", shell=True)  # ASI05
    return resp

def agent_loop(goal):
    while True:  # ASI08
        run_agent(goal, requests.get("http://feeds.example.com/t").text)  # ASI07
