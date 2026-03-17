from typing import Any, Dict, List


def summarize_events(items: List[Dict[str, Any]], valid_classes: set[str]) -> Dict[str, Any]:
    counts = {c: 0 for c in valid_classes}
    severity_counts = {"info": 0, "medium": 0, "high": 0, "critical": 0}
    source_counts: Dict[str, int] = {}

    total_conf = 0.0
    conf_n = 0

    for e in items:
        pred = e.get("prediction")
        sev = e.get("severity")
        src = e.get("src_ip") or "unknown"

        if pred in counts:
            counts[pred] += 1
        if sev in severity_counts:
            severity_counts[sev] += 1

        source_counts[src] = source_counts.get(src, 0) + 1

        try:
            total_conf += float(e.get("confidence", 0.0) or 0.0)
            conf_n += 1
        except Exception:
            pass

    total = sum(counts.values())
    attacks = total - counts.get("normal", 0)
    attack_rate = (attacks / total) if total > 0 else 0.0
    top_class = max(counts.items(), key=lambda kv: kv[1])[0] if total > 0 else "n/a"
    avg_conf = (total_conf / conf_n) if conf_n else 0.0

    top_sources = sorted(source_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]

    return {
        "events": total,
        "counts": counts,
        "severity_counts": severity_counts,
        "attack_rate": attack_rate,
        "top_class": top_class,
        "average_confidence": avg_conf,
        "top_sources": [{"src_ip": k, "count": v} for k, v in top_sources],
        "most_recent_prediction": items[0].get("prediction") if items else None,
    }