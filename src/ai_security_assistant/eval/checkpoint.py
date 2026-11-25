"""The resumable live-eval checkpoint (D44): append-only JSONL, flushed after every alert.

The first line is the header. It pins everything a resumed run must share with the run that wrote
the file (``PINNED_FIELDS``): any difference refuses to start and names the field. ``started`` is
informative and is not compared.

Every later line is one (configuration, sample) pair: what the provider call gave, the pipeline's
decision, a hash of the prompt that was sent and the latency. A later line for the same pair
replaces an earlier one (a retried error). The runner rebuilds every outcome by replaying the
stored reply through the pipeline, so nothing derived from a reply is trusted from the file.

A process killed in the middle of a write leaves an unfinished last line; it is cut off and that
pair runs again. Any other damage refuses to start.

A checkpoint holds model text. Its name must end with ``CHECKPOINT_SUFFIX``, which git ignores and
the gate refuses to see tracked or staged.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Final

CHECKPOINT_VERSION: Final = "1"
CHECKPOINT_SUFFIX: Final = ".checkpoint.jsonl"
PINNED_FIELDS: Final = (
    "checkpoint_version",
    "dataset",
    "dataset_sha256",
    "kb_version",
    "prompt_version",
    "naive_prompt_version",
    "seed",
    "provider",
    "model",
    "subset",
    "limit",
    "configs",
)
STARTED: Final = "started"

# What one provider call gave.
KIND_REPLY: Final = "reply"  # text came back (the strict parse may still refuse it)
KIND_MALFORMED: Final = "malformed"  # a reply that cannot be read as text, e.g. truncated
KIND_PROVIDER_ERROR: Final = "provider_error"  # timeout or HTTP error: retried only on request
KIND_REFUSED: Final = "refused_context_budget"  # no request made; final
KIND_NOT_CALLED: Final = "not_called"  # the detector blocked the alert
KINDS: Final = (KIND_REPLY, KIND_MALFORMED, KIND_PROVIDER_ERROR, KIND_REFUSED, KIND_NOT_CALLED)


class CheckpointError(ValueError):
    """The checkpoint cannot be used. The message is safe to print (no model or alert text)."""


Key = tuple[str, str]  # (configuration label, sample ID)


@dataclass(frozen=True)
class Record:
    config: str
    sample_id: str
    kind: str
    reason: str | None  # the MalformedReply code
    status: str  # the pipeline status of the outcome
    reasons: tuple[str, ...]  # the pipeline's reason codes
    prompt_sha256: str | None  # None when nothing was sent
    latency_ms: int | None
    raw_text: str | None = field(default=None, repr=False)  # untrusted model text

    @property
    def key(self) -> Key:
        return self.config, self.sample_id

    @property
    def eval_status(self) -> str:
        """The pipeline status, except that a failed or refused call keeps its own name."""
        return self.kind if self.kind in (KIND_PROVIDER_ERROR, KIND_REFUSED) else self.status

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=True, allow_nan=False)


_RECORD_KEYS: Final = frozenset(f.name for f in fields(Record))


def _optional(value: object, kind: type) -> bool:
    return value is None or type(value) is kind


def _record(row: object) -> Record | None:
    """The record of one parsed line, or None if it does not have the documented shape."""
    if not isinstance(row, dict) or set(row) != _RECORD_KEYS:
        return None
    reasons = row["reasons"]
    good = (
        all(type(row[name]) is str for name in ("config", "sample_id", "status"))
        and row["kind"] in KINDS
        and _optional(row["reason"], str)
        and isinstance(reasons, list)
        and all(type(code) is str for code in reasons)
        and _optional(row["prompt_sha256"], str)
        and _optional(row["latency_ms"], int)
        and _optional(row["raw_text"], str)
        and (row["kind"] == KIND_REPLY) is (row["raw_text"] is not None)
        and (row["kind"] == KIND_MALFORMED) is (row["reason"] is not None)
    )
    return Record(**{**row, "reasons": tuple(reasons)}) if good else None


def _loads(line: bytes) -> object:
    try:
        return json.loads(line)
    except (ValueError, RecursionError):  # includes bad UTF-8
        return None


def _differences(header: Mapping[str, Any], pinned: Mapping[str, object]) -> list[str]:
    return [
        f"{name} (checkpoint {_shown(header.get(name))}, now {_shown(pinned[name])})"
        for name in PINNED_FIELDS
        if name not in header or header[name] != pinned[name]  # a missing field differs too
    ]


def _shown(value: object) -> str:
    """A header value for a message: ASCII, bounded."""
    text = ascii(value)
    return text if len(text) <= 80 else f"{text[:77]}..."


def _append(path: Path, line: str) -> None:
    with path.open("ab") as handle:
        handle.write(line.encode("ascii") + b"\n")
        handle.flush()
        os.fsync(handle.fileno())  # a sleeping or unplugged laptop must not lose the alert


class Checkpoint:
    """An open checkpoint: the latest record of every pair, and ``append``."""

    def __init__(self, path: Path, started: str, records: dict[Key, Record]) -> None:
        self.path = path
        self.started = started
        self.records = records

    @classmethod
    def open(cls, path: Path, pinned: Mapping[str, object], started: str) -> Checkpoint:
        """Resume the checkpoint at ``path``, or start it if there is none.

        Raises ``CheckpointError`` (nothing is changed) if the file is not a checkpoint of this
        very run, and ``OSError`` if it cannot be read or written.
        """
        if set(pinned) != set(PINNED_FIELDS):
            raise ValueError("the header must pin exactly the documented fields")
        data = path.read_bytes() if path.exists() else b""
        if not data:
            header = {**pinned, STARTED: started}
            _append(path, json.dumps(header, ensure_ascii=True, allow_nan=False))
            return cls(path, started, {})
        end = data.rfind(b"\n") + 1  # what follows is an unfinished write
        lines = data[:end].split(b"\n")[:-1]
        header_row = _loads(lines[0]) if lines else None
        if not isinstance(header_row, dict) or not isinstance(header_row.get(STARTED), str):
            raise CheckpointError("the file is not a checkpoint: no readable header line")
        differs = _differences(header_row, pinned)
        if differs:
            raise CheckpointError(
                "the checkpoint belongs to another run; it differs in " + ", ".join(differs)
            )
        records: dict[Key, Record] = {}
        for number, line in enumerate(lines[1:], start=2):
            record = _record(_loads(line))
            if record is None:
                raise CheckpointError(f"checkpoint line {number} is damaged")
            records[record.key] = record
        if end < len(data):
            os.truncate(path, end)
        return cls(path, header_row[STARTED], records)

    def append(self, record: Record) -> None:
        _append(self.path, record.to_json())
        self.records[record.key] = record
