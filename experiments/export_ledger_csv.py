import json
import csv

with open("ledger_events.json") as f:
    events = json.load(f)

with open("ledger_events.csv", "w", newline="") as out:
    writer = csv.writer(out)

    writer.writerow([
        "timestamp",
        "device_id",
        "event_type",
        "details"
    ])

    for e in events:
        writer.writerow([
            e.get("timestamp"),
            e.get("device_id"),
            e.get("event_type"),
            e.get("details"),
        ])
