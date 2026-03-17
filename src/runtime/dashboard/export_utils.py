import csv
import io
from typing import Any, Dict, List


def events_to_csv(items: List[Dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "id", "ts", "prediction", "severity", "confidence",
        "policy_action", "status", "protocol",
        "src_ip", "src_port", "dst_ip", "dst_port"
    ])

    for e in items:
        writer.writerow([
            e.get("id"),
            e.get("ts"),
            e.get("prediction"),
            e.get("severity"),
            e.get("confidence"),
            e.get("policy_action"),
            e.get("status"),
            e.get("protocol"),
            e.get("src_ip"),
            e.get("src_port"),
            e.get("dst_ip"),
            e.get("dst_port"),
        ])

    return output.getvalue()