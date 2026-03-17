import json
from pathlib import Path
from typing import Any, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
NOTES_PATH = REPO_ROOT / "data" / "logs" / "event_notes.json"
NOTES_PATH.parent.mkdir(parents=True, exist_ok=True)


def _ensure_file() -> None:
    if not NOTES_PATH.exists():
        NOTES_PATH.write_text("{}", encoding="utf-8")


def load_notes() -> Dict[str, Any]:
    _ensure_file()
    try:
        with open(NOTES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_notes(data: Dict[str, Any]) -> None:
    _ensure_file()
    with open(NOTES_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_event_note(event_id: str) -> Dict[str, Any]:
    notes = load_notes()
    val = notes.get(event_id, {})
    return val if isinstance(val, dict) else {}


def set_event_note(
    event_id: str,
    note: Optional[str] = None,
    status: Optional[str] = None,
) -> Dict[str, Any]:
    notes = load_notes()
    current = notes.get(event_id, {})
    if not isinstance(current, dict):
        current = {}

    if note is not None:
        current["note"] = note
    if status is not None:
        current["status"] = status

    notes[event_id] = current
    save_notes(notes)
    return current