#!/usr/bin/env python3

import fcntl
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

START_FROM_NULL = os.environ.get("CUPS_START_FROM_NULL", "false").lower() == "true"

GRAYLOG_HOST = os.environ.get(
    "GRAYLOG_GELF_HOST",
    "127.0.0.1",
)

GRAYLOG_PORT = int(
    os.environ.get("GRAYLOG_GELF_PORT", "12201")
)

JOURNAL_UNIT = os.environ.get("CUPS_JOURNAL_UNIT", "cups")

STATE_DIR = Path(
    os.environ.get("CUPS_STATE_DIR", "/var/lib/cups-graylog")
)
STATE_FILE = STATE_DIR / "state.json"
LOCK_FILE = STATE_DIR / "agent.lock"

# Initial scan window on the first launch.
INITIAL_LOOKBACK = int(os.environ.get("CUPS_INITIAL_LOOKBACK", "600"))

# How long to retain deduplication keys.
SENT_RETENTION = 30 * 24 * 60 * 60

# Discard incomplete jobs only after this interval.
INCOMPLETE_RETENTION = 7 * 24 * 60 * 60

# GELF UDP packets should remain small.
MAX_DATAGRAM_SIZE = 8192


ARGV_RE = re.compile(
    r'\[Job\s+(\d+)\]\s+argv\[(\d+)\]="(.*)"\s*$'
)

CREATED_AT_RE = re.compile(
    r'(?:^|\s)time-at-creation=(\d+)(?:\s|$)'
)


# ============================================================
# State management
# ============================================================

def initial_state():
    now = int(time.time())

    return {
        "version": 1,
        "cursor": None,
        "initial_since": now - INITIAL_LOOKBACK,
        "last_scan": now,
        "pending_jobs": {},
        "pending_send": {},
        "sent_keys": {},
    }


def load_state():
    if not STATE_FILE.exists():
        return initial_state()

    with STATE_FILE.open("r", encoding="utf-8") as file:
        state = json.load(file)

    if state.get("version") != 1:
        raise RuntimeError("Unsupported state.json version")

    state.setdefault("cursor", None)
    state.setdefault("initial_since", int(time.time()) - INITIAL_LOOKBACK)
    state.setdefault("last_scan", int(time.time()))
    state.setdefault("pending_jobs", {})
    state.setdefault("pending_send", {})
    state.setdefault("sent_keys", {})

    return state


def save_state(state):
    """Atomically replace state.json with the new state."""

    STATE_DIR.mkdir(parents=True, exist_ok=True)

    temp_file = STATE_FILE.with_suffix(".json.tmp")

    with temp_file.open("w", encoding="utf-8") as file:
        json.dump(
            state,
            file,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        file.flush()
        os.fsync(file.fileno())

    os.replace(temp_file, STATE_FILE)

    # Persist the directory entry where supported.
    directory_fd = os.open(STATE_DIR, os.O_RDONLY)

    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


# ============================================================
# Journal reader
# ============================================================

def read_journal(state, now):
    command = [
        "journalctl", "-u", JOURNAL_UNIT,
        "--no-pager", "-o", "json",
        f"--until=@{now}",
    ]

    cursor = state.get("cursor")

    if cursor:
        command.append(f"--after-cursor={cursor}")
    else:
        command.append(
            f"--since=@{state['initial_since']}"
        )

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    events = []

    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        events.append(event)

    return events


# ============================================================
# CUPS event parsing and aggregation
# ============================================================

def job_identity(host, job_id):
    return f"{host}:{job_id}"


def collect_events(state, events):
    pending_jobs = state["pending_jobs"]
    new_jobs = 0

    for event in events:
        message = event.get("MESSAGE", "")
        match = ARGV_RE.search(message)

        if not match:
            continue

        journal_job_id = int(match.group(1))
        argv_index = int(match.group(2))
        argv_value = match.group(3)

        host = (
            event.get("_HOSTNAME")
            or socket.gethostname()
        )

        key = job_identity(host, journal_job_id)

        journal_timestamp = int(
            event.get("__REALTIME_TIMESTAMP", "0")
        ) // 1_000_000

        job = pending_jobs.setdefault(
            key,
            {
                "host": host,
                "journal_job_id": journal_job_id,
                "argv": {},
                "first_seen": journal_timestamp or int(time.time()),
                "last_seen": journal_timestamp or int(time.time()),
            },
        )

        # Save the latest value for each argv index.
        job["argv"][str(argv_index)] = argv_value

        job["last_seen"] = (
            journal_timestamp or int(time.time())
        )

        new_jobs += 1

    return new_jobs


def make_job_key(host, job_id, created_at):
    identity = f"{host}|{job_id}|{created_at}"

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


def build_gelf_record(job):
    argv = job["argv"]

    required_indexes = ("0", "1", "2", "3", "4", "5")

    if not all(index in argv for index in required_indexes):
        return None

    try:
        job_id = int(argv["1"])
        copies = int(argv["4"])
    except ValueError:
        return None

    created_match = CREATED_AT_RE.search(argv["5"])

    if not created_match:
        return None

    created_at = int(created_match.group(1))

    if created_at <= 0:
        return None

    host = job["host"]

    job_key = make_job_key(
        host,
        job_id,
        created_at,
    )

    record = {
        "version": "1.1",
        "host": host,
        "short_message": f"CUPS print job {job_id}",
        "timestamp": created_at,
        "_job_key": job_key,
        "_job_id": job_id,
        "_user": argv["2"],
        "_printer": argv["0"],
        "_file_name": argv["3"],
        "_copies": copies,
        "_created_at": created_at,
    }

    # Preserve original argv values for diagnostics.
    for index, value in argv.items():
        record[f"_argv_{index}"] = value

    return job_key, record


def finalize_jobs(state, now):
    pending_jobs = state["pending_jobs"]
    pending_send = state["pending_send"]
    sent_keys = state["sent_keys"]

    completed = 0
    expired = 0

    for key, job in list(pending_jobs.items()):
        result = build_gelf_record(job)

        if result is not None:
            job_key, record = result

            if (
                job_key not in sent_keys
                and job_key not in pending_send
            ):
                pending_send[job_key] = record

            # The complete record is now in pending_send
            # and will be saved before transmission.
            del pending_jobs[key]
            completed += 1
            continue

        last_seen = int(job.get("last_seen", now))

        if now - last_seen > INCOMPLETE_RETENTION:
            print(
                f"WARNING: discarding incomplete job {key}",
                file=sys.stderr,
            )

            del pending_jobs[key]
            expired += 1

    return completed, expired


# ============================================================
# GELF UDP sender
# ============================================================

def send_udp(sock, address, record):
    packet = json.dumps(
        record,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(packet) > MAX_DATAGRAM_SIZE:
        raise ValueError(
            f"GELF datagram too large: {len(packet)} bytes"
        )

    # UDP sendto does not confirm Graylog receipt.
    sent_bytes = sock.sendto(packet, address)

    if sent_bytes != len(packet):
        raise OSError("Incomplete UDP datagram send")


def flush_pending(state):
    pending_send = state["pending_send"]
    sent_keys = state["sent_keys"]

    if not pending_send:
        return 0

    addresses = socket.getaddrinfo(
        GRAYLOG_HOST,
        GRAYLOG_PORT,
        type=socket.SOCK_DGRAM,
    )

    if not addresses:
        raise OSError("Could not resolve Graylog address")

    family, socktype, proto, _, address = addresses[0]

    sent_count = 0

    with socket.socket(family, socktype, proto) as sock:
        for job_key, record in list(pending_send.items()):
            try:
                send_udp(sock, address, record)

            except (OSError, ValueError) as error:
                print(
                    f"UDP send failed for {job_key}: {error}",
                    file=sys.stderr,
                )

                # Keep the record for a future retry.
                continue

            # sendto succeeded locally. This does NOT mean
            # Graylog has confirmed or indexed the message.
            sent_keys[job_key] = int(time.time())
            del pending_send[job_key]

            # Persist each transition separately.
            save_state(state)

            print(f"UDP datagram sent for job {job_key}")
            sent_count += 1

    return sent_count


# ============================================================
# Cleanup and main
# ============================================================

def cleanup_state(state, now):
    sent_keys = state["sent_keys"]

    for key, sent_at in list(sent_keys.items()):
        if now - int(sent_at) > SENT_RETENTION:
            del sent_keys[key]


def main():
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Prevent overlapping executions.
    with LOCK_FILE.open("w", encoding="utf-8") as lock:
        try:
            fcntl.flock(
                lock.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            print("Another agent instance is running")
            return 0

        if START_FROM_NULL:
            print("Starting from null cursor as requested")
            state = initial_state()
        else:
            state = load_state()
    
        now = int(time.time())

        # Read journal events after the saved cursor.
        events = read_journal(state, now)

        # Apply all events to persistent in-memory state.
        parsed = collect_events(state, events)

        # Advance the cursor to the last event actually read.
        if events:
            last_cursor = events[-1].get("__CURSOR")

            if last_cursor:
                state["cursor"] = last_cursor

        completed, expired = finalize_jobs(state, now)

        state["last_scan"] = now
        cleanup_state(state, now)

        # Persist cursor, partial jobs and outgoing queue
        # before attempting any network transmission.
        save_state(state)

        print(f"Journal events: {len(events)}")
        print(f"argv messages processed: {parsed}")
        print(f"Completed jobs queued: {completed}")
        print(f"Incomplete jobs expired: {expired}")

        # Send pending records. Failures remain queued.
        flush_pending(state)

        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        OSError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"Agent error: {error}", file=sys.stderr)
        sys.exit(1)
