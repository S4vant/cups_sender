#!/usr/bin/env python3

import json
import re
import subprocess
import sys
from collections import defaultdict


ARGV_RE = re.compile(
    r'\[Job\s+(\d+)\]\s+argv\[(\d+)\]="(.*)"\s*$'
)

CREATED_AT_RE = re.compile(r'(?:^|\s)time-at-creation=(\d+)(?:\s|$)')


def read_journal():
    result = subprocess.run(
        [
            "journalctl",
            "-u", "cups",
            "--since", "today",
            "--no-pager",
            "-o", "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.splitlines()


def parse_jobs(lines):
    jobs = defaultdict(
        lambda: {"argv": {}, "host": None}
    )

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        message = event.get("MESSAGE", "")
        match = ARGV_RE.search(message)

        if not match:
            continue

        job_id = int(match.group(1))
        argv_index = int(match.group(2))
        argv_value = match.group(3)

        job = jobs[job_id]
        job["argv"][argv_index] = argv_value
        job["host"] = event.get("_HOSTNAME", job["host"])

    result = []

    for job_id, job in jobs.items():
        argv = job["argv"]

        # Для первой версии нужны параметры argv[0]–argv[5].
        if not all(i in argv for i in range(6)):
            continue

        extra = argv[5]
        created_match = CREATED_AT_RE.search(extra)

        try:
            copies = int(argv[4])
        except ValueError:
            copies = None

        record = {
            "job_id": int(argv[1]),
            "host": job["host"],
            "printer": argv[0],
            "user": argv[2],
            "file_name": argv[3],
            "copies": copies,
            "created_at": (
                int(created_match.group(1))
                if created_match else None
            ),
            "argv": {
                str(index): value
                for index, value in sorted(argv.items())
            },
        }

        result.append(record)

    result.sort(
        key=lambda job: (
            job["created_at"] or 0,
            job["job_id"],
        )
    )

    return result


def main():
    try:
        lines = read_journal()
        jobs = parse_jobs(lines)
    except subprocess.CalledProcessError as error:
        print(
            f"Ошибка journalctl: {error.stderr}",
            file=sys.stderr,
        )
        return 1
    except FileNotFoundError:
        print("Не найден journalctl.", file=sys.stderr)
        return 1

    for job in jobs:
        print(json.dumps(job, ensure_ascii=False))

    print(
        f"Найдено заданий: {len(jobs)}",
        file=sys.stderr,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())