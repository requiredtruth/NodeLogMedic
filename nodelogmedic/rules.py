from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class Rule:
    """One deterministic diagnosis rule applied to already-redacted text."""

    rule_id: str
    severity: str
    title: str
    pattern: re.Pattern[str]
    explanation: str
    checks: tuple[str, ...]


def _rule(rule_id: str, severity: str, title: str, pattern: str, explanation: str, *checks: str) -> Rule:
    return Rule(rule_id, severity, title, re.compile(pattern, re.IGNORECASE), explanation, checks)


RULES: tuple[Rule, ...] = (
    _rule(
        "disk-space-exhausted", "critical", "Node storage cannot accept writes",
        r"no space left on device|disk(?: is)? full|insufficient disk space",
        "The log contains an operating-system storage exhaustion error.",
        "Check free bytes and inodes on the node data volume.",
        "Stop repeated restart loops before choosing a recovery action.",
    ),
    _rule(
        "database-integrity", "critical", "Database integrity error reported",
        r"database.*(?:corrupt|corruption)|corruption detected|invalid (?:table )?checksum",
        "The client reported corruption or checksum failure; this rule does not infer the cause.",
        "Preserve logs and verify backups before destructive repair or resync steps.",
        "Consult the exact client and version recovery documentation.",
    ),
    _rule(
        "memory-exhaustion", "critical", "Process or host memory exhausted",
        r"out of memory|oom[- ]killer|killed process.*(?:geth|besu|nethermind|reth|beacon|validator)",
        "The log contains an explicit memory exhaustion or process-kill signal.",
        "Check peak resident memory, cgroup limits, and kernel OOM records.",
        "Reduce concurrency or cache only after identifying the constrained process.",
    ),
    _rule(
        "consensus-disconnected", "error", "Execution and consensus clients are not exchanging updates",
        r"no beacon client seen|no consensus updates received|consensus client.*(?:not connected|unavailable)|engine api.*unavailable",
        "The execution/consensus link appears unavailable or stale in the supplied lines.",
        "Confirm both clients are running on the intended hosts and ports.",
        "Check the shared Engine API JWT path and recent clocks without publishing the secret.",
    ),
    _rule(
        "engine-jwt-auth", "error", "Engine API authentication failed",
        r"(?:jwt|engine api).*(?:authentication failed|unauthorized|invalid token)|(?:authentication failed|unauthorized).*(?:jwt|engine api)",
        "The log explicitly associates Engine API or JWT authentication with rejection.",
        "Compare the configured JWT file locations and file contents locally.",
        "Check file permissions and restart only the component whose configuration changed.",
    ),
    _rule(
        "file-descriptor-limit", "error", "Open-file limit reached",
        r"too many open files|file descriptor limit",
        "The process reported file descriptor exhaustion.",
        "Inspect the process limit and current descriptor count.",
        "Check for connection churn before raising limits.",
    ),
    _rule(
        "port-conflict", "error", "Configured listening address is already occupied",
        r"bind.*address already in use|address already in use.*(?:port|listen)",
        "Another socket already owns a requested listening address or port.",
        "Identify the local listening process without publishing addresses.",
        "Resolve duplicate services or configuration before restarting.",
    ),
    _rule(
        "peer-connectivity", "warning", "Peer discovery or connectivity is stalled",
        r"looking for peers|peer count\D+0\b|\b0 peers\b|unable to find.*peers",
        "The supplied lines show zero peers or continuing peer discovery.",
        "Check time synchronization, firewall rules, discovery ports, and advertised addresses.",
        "Compare peer count over a longer window before treating one line as an outage.",
    ),
    _rule(
        "network-timeout", "warning", "Repeated network timeout reported",
        r"context deadline exceeded|i/o timeout|connection timed out|request timeout",
        "A network operation exceeded its deadline; the endpoint and root cause remain unknown.",
        "Group failures by component and time window using the redacted evidence.",
        "Check latency, packet loss, DNS, and upstream availability.",
    ),
    _rule(
        "sync-maintenance", "info", "State synchronization or healing is active",
        r"state heal(?:ing)?|state snapshot generation|snapshot extension|syncing.*state",
        "The client reports state synchronization or maintenance activity, not necessarily failure.",
        "Track progress counters across time before intervening.",
        "Check disk throughput if progress remains unchanged across a meaningful interval.",
    ),
)
