
import json
import os
from datetime import date, timedelta


DATA_DIR = "data"
HISTORY_FILE = os.path.join(DATA_DIR, "scan_history.json")


def main() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)

    today = date.today()

    # (dni wstecz, nazwa pliku, liczba zagrożeń)
    # 7 punktów z niezerowymi wartościami, żeby wykres był ładnie pofalowany.
    samples = [
        (6, "payment_service.py", 3),
        (5, "auth_controller.py", 7),
        (4, "legacy_crypto.py", 2),
        (3, "docker_entrypoint.sh", 10),
        (2, "user_profile.js", 5),
        (1, "main.py", 8),
        (0, "api_gateway.py", 4),
    ]

    entries = []
    for days_ago, fname, threats in samples:
        d = today - timedelta(days=days_ago)
        entries.append(
            {
                "file": fname,
                "date": d.strftime("%Y-%m-%d"),
                "threats": int(threats),
            }
        )

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=4)

    print(f"Wrote {len(entries)} demo entries to {HISTORY_FILE}")


if __name__ == "__main__":
    main()