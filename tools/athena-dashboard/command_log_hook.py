"""Client the SDK agent uses to write the command evidence log.

Never raises into the agent loop: on any transport failure it spools to disk
(command_log.append_spool) for later server-side ingest.
"""
import asyncio
import logging
import time

import httpx

import command_log as cl

logger = logging.getLogger("athena.command_log_hook")

# 1 attempt + 3 backoffs
_RETRY_BACKOFF = (0.25, 0.5, 1.0)


def classify_backend(tool_name: str):
    """Return the evidence backend for a tool name, or None if it is not logged."""
    if tool_name == "Bash":
        return "host"
    if "kali_external" in tool_name:
        return "kali_external"
    if "kali_internal" in tool_name:
        return "kali_internal"
    return None


class CommandLogClient:
    def __init__(self, base_url: str, engagement_id: str, evidence_dir_resolver=None):
        self.base_url = base_url.rstrip("/")
        self.engagement_id = engagement_id
        self._resolver = evidence_dir_resolver or cl.resolve_evidence_dir
        self._seq_by_tool = {}

    async def _post(self, path: str, payload: dict) -> dict:
        from auth import agent_request_headers
        async with httpx.AsyncClient(timeout=5.0, headers=agent_request_headers()) as client:
            last = None
            for attempt in range(1 + len(_RETRY_BACKOFF)):
                try:
                    resp = await client.post(self.base_url + path, json=payload)
                    if resp.status_code == 503:
                        raise httpx.HTTPError("503 locked")
                    resp.raise_for_status()
                    return resp.json()
                except httpx.HTTPError as e:
                    last = e
                    if attempt < len(_RETRY_BACKOFF):
                        await asyncio.sleep(_RETRY_BACKOFF[attempt])
            raise last

    def _evidence_dir(self):
        return self._resolver(self.engagement_id)

    def _spool(self, record: dict) -> None:
        try:
            cl.append_spool(self._evidence_dir(), record)
        except Exception as e:  # never raise into the agent loop
            logger.error("command-log spool write failed: %s", str(e)[:160])

    async def start(self, agent: str, tool_name: str, tool_use_id: str, input: dict) -> None:
        backend = classify_backend(tool_name)
        if backend is None:
            return
        payload = {"engagement_id": self.engagement_id, "agent": agent or "", "backend": backend,
                   "tool": tool_name, "tool_use_id": tool_use_id, "input": input or {}}
        try:
            body = await self._post("/api/command-log/start", payload)
            self._seq_by_tool[tool_use_id] = body["seq"]
        except Exception as e:
            logger.warning("command-log start spooled (%s): %s", tool_use_id, str(e)[:120])
            self._spool({
                "kind": "start", "agent": agent or "", "backend": backend, "tool": tool_name,
                "tool_use_id": tool_use_id, "input": input or {},
                "client_ts": int(time.time() * 1000)})

    async def complete(self, tool_use_id: str, output: str, is_error: bool) -> None:
        # start_seq is None when the start was spooled (or never reached the server);
        # ingest pairs the spooled complete to its start by tool_use_id.
        start_seq = self._seq_by_tool.pop(tool_use_id, None)
        if start_seq is not None:
            payload = {"engagement_id": self.engagement_id, "start_seq": start_seq,
                       "output": output, "is_error": bool(is_error)}
            try:
                await self._post("/api/command-log/complete", payload)
                return
            except Exception as e:
                logger.warning("command-log complete spooled (%s): %s", tool_use_id, str(e)[:120])
        self._spool({
            "kind": "complete", "tool_use_id": tool_use_id, "output": output,
            "is_error": bool(is_error), "client_ts": int(time.time() * 1000),
            **({"start_seq": start_seq} if start_seq is not None else {})})
