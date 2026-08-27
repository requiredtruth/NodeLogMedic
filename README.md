# NodeLogMedic

**Local blockchain node log diagnosis with automatic secret, wallet, IP, URL, and filesystem-path redaction.** NodeLogMedic streams a log once, redacts each line before matching or retaining evidence, groups repeated symptoms, and emits a compact terminal board or stable JSON.

```bash
python -m nodelogmedic examples/node.log --color always
```

```text
NODE LOG MEDIC
========================================================================
Lines 5  Redactions 6  Findings 3

SEVERITY  COUNT  FINDING
------------------------------------------------------------------------
ERROR         1  Execution and consensus clients are not exchanging updates [consensus-disconnected]
ERROR         1  Engine API authentication failed [engine-jwt-auth]
WARNING       1  Peer discovery or connectivity is stalled [peer-connectivity]
```

The example is a synthetic fixture containing handled symptom phrases such as `no beacon client seen`, `Engine API JWT authentication failed`, and `Looking for peers`. Its hosts, paths, token, and wallet are deliberately fake and are redacted in actual evidence output.

## Problems it recognizes

NodeLogMedic directly handles common search and terminal symptoms including:

- `no space left on device`
- `database corruption` and `invalid checksum`
- `out of memory` and node-process OOM kills
- `no beacon client seen` or `no consensus updates received`
- Engine API or JWT `authentication failed`
- `too many open files`
- `bind: address already in use`
- `looking for peers`, `0 peers`, and peer-count zero
- `context deadline exceeded`, `i/o timeout`, and connection timeouts
- state healing and snapshot-generation progress

A match is a symptom, not proof of root cause. Checks are deliberately phrased as verification steps rather than automated repair commands.

## Concrete distinction

General log processors often forward data to a service or require a full observability stack. NodeLogMedic is a zero-runtime-dependency, local first-pass tool for execution and consensus client support bundles. It redacts before evidence retention, bounds evidence per rule, preserves occurrence counts, and exposes a versioned deterministic report schema.

It is not a replacement for client-specific documentation, metrics, traces, or an operator's incident process.

## Use

Python 3.11 or newer is required.

Analyze a local file:

```bash
python -m nodelogmedic /var/log/YOUR_NODE.log
```

Stream from another process without writing an intermediate copy:

```bash
journalctl -u YOUR_NODE.service --since today | python -m nodelogmedic -
```

Machine-readable evidence:

```bash
python -m nodelogmedic examples/node.log --format json > report.json
```

NodeLogMedic exits `0` when no warning/error/critical rule matches, `1` when such findings exist, and `2` for invalid input or arguments. This makes it usable in scripts without equating a diagnosis with a parser failure.

### Optional local AI commentary

```bash
python -m nodelogmedic examples/node.log --format json \
  --ai-endpoint http://127.0.0.1:8080 \
  --ai-model your-local-model
```

Only an already-redacted report can reach the AI layer, and the endpoint must be HTTP(S) on `localhost`, `127.0.0.1`, or `::1`. AI text cannot alter deterministic findings.

## Redaction boundary

The built-in redactor targets credential assignments, bearer tokens, JWTs, HTTP/WebSocket URLs, 32-byte hex values, EVM addresses, IPv4/IPv6 addresses, and common absolute Unix/Windows paths. Long lines are bounded before analysis.

Redaction is defense in depth, not a mathematical guarantee. Review any report before publishing it. Unusual secret encodings, split secrets, hostnames outside URLs, application-specific identifiers, and multiline data may remain.

## Typed API and schema

```python
from nodelogmedic import DiagnosisConfig, diagnose_lines

report = diagnose_lines(
    ["WARN no beacon client seen at 192.0.2.10\n"],
    DiagnosisConfig(max_evidence=2, max_line_length=4096),
)
```

- `max_evidence`: `1..20`
- `max_line_length`: `256..65536`
- report schema: [`schema/report.schema.json`](schema/report.schema.json)
- public functions have strict bounds, stable return shapes, and deterministic ordering

## One-command verification

```bash
python -m unittest discover -s tests -v
```

The test suite verifies redaction, diagnosis after redaction, bounded evidence, stable clean output, parameter bounds, and loopback-only AI access.

## Request funded development

Donations fund additional production. After a confirmed donation, use the repository's funded-direction issue template with the asset, exact network, public transaction hash, and requested rule, client fixture, redaction shape, or output feature. Read [SUPPORT.md](SUPPORT.md) for attribution and safety limits.

## License

Apache-2.0. See [LICENSE](LICENSE).


## Install and run

```sh
chmod +x install.sh run.sh
./install.sh
./run.sh --help
```


## Standard launcher

`./run.sh` is the normal entry point. It runs `./install.sh` automatically when setup is missing, then opens the PySide6 control panel with live output and actions for the demo, tests, repair, and stop. Use `./cli.sh` for CLI-only operation.
