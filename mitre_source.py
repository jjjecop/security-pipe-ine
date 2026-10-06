import csv, re 

csv.field_size_limit(10_000_000)

CHILD_OF_PATTERN = re.compile(r"NATURE:ChildOf:CWE ID:(\d+):VIEW ID:1000")

def load_mitre_mitigations(csv_path: str = "mitre/1000.csv") -> dict:
    result = {}
    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            cwe_id = f"CWE-{row.get('CWE-ID')}"
            mitigations = (row.get("Potential Mitigations") or "").replace("::", "\n").strip()
            parents = [f"CWE-{p}" for p in CHILD_OF_PATTERN.findall(row.get("Related Weaknesses") or "")]
            result[cwe_id] = {
                "name": row.get("Name") or "",
                "mitigations": mitigations,
                "parents": parents,
                "children": [],
            }

    for cwe_id, info in result.items():
        for parent in info["parents"]:
            if parent in result:
                result[parent]["children"].append(cwe_id)

    return result

def collect_children_mitigations(mitre: dict, cwe_id: str, max_chars: int = 8000) -> tuple[str, list[str]]:
    info = mitre.get(cwe_id)
    if info is None:
        return "", []

    parts = []
    used = []
    total = 0
    for child in info["children"]:
        child_info = mitre.get(child)
        if not child_info or not child_info["mitigations"]:
            continue
        block = f"[{child} {child_info['name']}]\n{child_info['mitigations']}"
        if total + len(block) > max_chars:
            break

        parts.append(block)
        used.append(child)
        total += len(block)

    return "\n\n".join(parts), used