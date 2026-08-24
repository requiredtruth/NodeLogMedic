from __future__ import annotations

import json
from urllib import parse, request


def explain_local(report: dict[str, object], endpoint: str, model: str, *, timeout: float = 60.0) -> str:
    """Request bounded commentary from a loopback OpenAI-compatible server."""
    parsed = parse.urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("AI explanations require an HTTP loopback endpoint")
    url = endpoint.rstrip("/")
    if not url.endswith("/chat/completions"):
        url += "/v1/chat/completions"
    prompt = (
        "Summarize this already-redacted deterministic node-log report. Do not infer a "
        "root cause, missing secrets, hosts, identities, wallet data, or unseen configuration. "
        "Keep checks separate from facts.\n" + json.dumps(report, sort_keys=True)
    )
    body = json.dumps({"model": model, "temperature": 0, "messages": [{"role": "user", "content": prompt}]}).encode()
    req = request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with request.urlopen(req, timeout=timeout) as response:
        payload = json.load(response)
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("local AI endpoint returned no explanation") from exc
    if not isinstance(content, str):
        raise ValueError("local AI explanation must be text")
    return content
