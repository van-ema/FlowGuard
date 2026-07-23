import json
from pathlib import Path

report = json.loads(Path("./logs/secret-to-network-protect.report.json").read_text())

for warning in report["warnings"]:
    print(
        f"{warning['index']}: "
        f"seq={warning['sequence']} "
        f"kind={warning['kind']} "
        f"msg={warning['message']}"
    )