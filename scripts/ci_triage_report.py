#!/usr/bin/env python3
"""Explain a recognized RP05 proof-package failure in the Actions summary."""

from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_triage_collect import COMMAND, FINDINGS, PROOF_COMMAND


MODEL = "gpt-6-luna"
SECRET = "HEGEMON_CI_TRIAGE_OPENAI_API_KEY"
MAX_RESPONSE_BYTES = 16 * 1024
UNAVAILABLE = "The API returned no usable explanation."
SENSITIVE = re.compile(
    r"(?:sk-|gh[pousr]_|github_pat_|AKIA|ASIA|-----BEGIN |Bearer\s)"
    r"|(?:password|token|secret|api[_ -]?key)\s*[:=]"
    r"|[A-Za-z0-9_+/=-]{32,}|https?://|[\w.+-]+@[\w.-]+",
    re.IGNORECASE,
)


def interpretation(raw, key):
    """Accept a single completed text message. Suppress secret-like output."""
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError
    response = json.loads(raw)
    if not isinstance(response, dict) or response.get("status") != "completed":
        raise ValueError
    output = response.get("output")
    if not isinstance(output, list) or not all(isinstance(item, dict) for item in output):
        raise ValueError
    messages = [item for item in output if item.get("type") != "reasoning"]
    if len(messages) != 1:
        raise ValueError
    message = messages[0]
    if (message.get("type"), message.get("role"), message.get("status")) != (
        "message", "assistant", "completed"
    ):
        raise ValueError
    content = message.get("content")
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        raise ValueError
    answer = content[0].get("text")
    if content[0].get("type") != "output_text" or not isinstance(answer, str):
        raise ValueError
    # One indented line stays inert in GitHub Flavored Markdown, even with backticks or HTML.
    text = " ".join(answer.split())
    if not 1 <= len(text) <= 480 or not text.isprintable() or key in text or SENSITIVE.search(text):
        raise ValueError
    return "Model interpretation (tentative)\n\n    " + text


def explain(evidence, key):
    if not key:
        return "Model interpretation skipped because the dedicated project key is missing."
    if not key.isascii() or not key.isprintable() or any(c.isspace() for c in key):
        return "Model interpretation skipped because the dedicated project key is malformed."
    body = json.dumps({
        "model": MODEL,
        "instructions": (
            "Explain one plausible meaning of this RP05 proof-package CI failure "
            "in one short plain English sentence. Use only the supplied evidence. "
            "Omit commands, actions, links and claims about proof validity."
        ),
        "input": json.dumps(evidence),
        "reasoning": {"effort": "none"},
        "max_output_tokens": 128,
        "store": False,
    })
    # Direct TLS to a fixed host. HTTPSConnection follows no redirects or proxy environment.
    try:
        with closing(http.client.HTTPSConnection("api.openai.com", timeout=20)) as connection:
            connection.request("POST", "/v1/responses", body=body, headers={
                "Authorization": "Bearer " + key,
                "Content-Type": "application/json",
            })
            response = connection.getresponse()
            if response.status != 200:
                return f"Model interpretation unavailable (HTTP {response.status})."
            return interpretation(response.read(MAX_RESPONSE_BYTES + 1), key)
    except (OSError, http.client.HTTPException):
        return "The API request could not be completed."
    except (ValueError, RecursionError):
        return UNAVAILABLE


def summary(mode, finding, key):
    if (mode not in ("run", "smoke") or finding not in FINDINGS
            or (mode == "smoke" and finding != "source_hash")):
        return "### RP05 CI triage\n\nSkipped because the mode or diagnostic is unsupported.\n"
    error, context = FINDINGS[finding]
    command = COMMAND
    title = "RP05 CI triage"
    verification = f"At the failed run's commit, rerun `{COMMAND}` to reproduce the guard result."
    if finding == "source_hash":
        verification = (
            "At the failed run's commit, find the module from the original error in "
            "`formal/rp05/source-manifest.json` and compare its staged file's SHA-256 "
            "with the recorded digest."
        )
    elif finding == "kernel_memory":
        command = PROOF_COMMAND
        verification = (
            "Inspect the first Lean error in the linked cold proof step and confirm that "
            "the kernel reports excessive memory consumption before the wrapper exits."
        )
    if mode == "smoke":
        title += " (synthetic smoke fixture)"
        verification = f"Run `{COMMAND}` on the workflow commit to compare the clean result with this fixture."
    evidence = {"command": command, "first_error": error, "context": context}
    return (
        f"### {title}\n\n"
        f"Command\n\n    {command}\n\nFirst error (sanitized)\n\n    {error}\n\n"
        f"{context}\n\n{explain(evidence, key)}\n\n"
        f"**Suggested verification**\n\n{verification}\n"
    )


if __name__ == "__main__":
    result = summary(os.getenv("TRIAGE_MODE"), os.getenv("TRIAGE_FINDING"), os.getenv(SECRET))
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as out:
        out.write(result)
