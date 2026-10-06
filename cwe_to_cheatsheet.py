import re, os, math

def parse_owasp_index(index_file_path: str) -> dict:
    with open(index_file_path, "r", encoding="utf-8") as f:
        content = f.read()

    category_files = {}
    current_category = None 

    for line in content.split("\n"):
        category_match = re.match(r"##\s*\[([A-Z0-9:]+)", line)
        if category_match:
            current_category = category_match.group(1)
            category_files[current_category] = []
            continue

        file_match = re.search(r"\((cheatsheets/[^)]+\.md)\)", line)
        if file_match and current_category:
            filename = file_match.group(1).replace("cheatsheets/", "")
            category_files[current_category].append(filename)

    return category_files 


SYNONYM_MAP = {
    "neutralization": ["injection"],
    "special":        ["injection"],
    "cleartext":      ["transport", "transmission", "tls"],
    "transmission":   ["transport", "tls"],
    "random":         ["cryptographic"],
    "credentials":    ["secrets"],
    "protected":      ["secrets"],
    "consumption":    ["denial", "service"],
    "resource":       ["denial", "service"],
    "amplification":  ["denial", "service"],
    "algorithmic":    ["denial", "service", "regular", "expression"],
    "complexity":     ["denial", "service", "regular", "expression"],
    "throttling":     ["denial", "service"],
    "platform":       ["denial", "service"],
    "missing":        ["logging"],
    "sphere":         ["direct", "object", "reference"],
}

def find_best_match_in_category(cwe_description: str, candidate_files: list) -> str | None:
    if not candidate_files:
        return None

    keywords = re.findall(r'\w+', cwe_description.lower())
    keywords = [k for k in keywords if len(k) > 3]

    expanded = set(keywords)
    for kw in keywords:
        if kw in SYNONYM_MAP:
            expanded.update(SYNONYM_MAP[kw])

    best_match = None
    best_score = 0
    for filename in candidate_files:
        filename_lower = filename.lower().replace("_", " ")
        score = sum(1 for kw in expanded if kw in filename_lower)
        if score > best_score:
            best_score = score
            best_match = filename

    return best_match


def find_cheatsheet_with_fallback(cwe_description: str, owasp_category: str, index_data: dict, cheatsheets_folder: str) -> str | None:
    code_match = re.match(r"(A\d{1,2}:\d{4})", owasp_category or "")
    category_code = code_match.group(1) if code_match else owasp_category

    category_files = index_data.get(category_code, [])
    result = find_best_match_in_category(cwe_description, category_files)

    if result is not None:
        return result

    print(f"  (ไม่เจอใน Index หมวด {category_code} กำลังค้นหาทั้งโฟลเดอร์...)")

    all_files = os.listdir(cheatsheets_folder)
    return find_best_match_in_category(cwe_description, all_files)


def find_content_candidates(cwe_description: str, cheatsheets_folder: str, top_n: int = 8) -> list[str]:
    desc_lower = cwe_description.lower().replace("-", " ")
    words = re.findall(r'[a-z]+', desc_lower)
    words = [w for w in words if w not in {"of", "or", "and", "a", "the", "to", "in", "on", "with", "for"}]

    phrases = set()
    for n in (3, 2):
        for i in range(len(words) - n + 1):
            phrases.add(" ".join(words[i:i+n]))

    single_keywords = set(w for w in words if len(w) > 3)
    expanded = set(single_keywords)
    for kw in single_keywords:
        if kw in SYNONYM_MAP:
            expanded.update(SYNONYM_MAP[kw])

    phrase_scores = []
    single_scores = []
    for filename in os.listdir(cheatsheets_folder):
        filepath = os.path.join(cheatsheets_folder, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read().lower().replace("-", " ")
        except Exception as e:
            continue

        p_score = sum(content.count(p) for p in phrases)
        if p_score > 0:
            phrase_scores.append((p_score, filename))

        s_score = sum(content.count(kw) for kw in expanded)
        if s_score > 0:
            single_scores.append((s_score, filename))

    if phrase_scores:
        phrase_scores.sort(reverse=True)
        return [filename for _, filename in phrase_scores[:top_n]]

    single_scores.sort(reverse=True)
    return [filename for _, filename in single_scores[:top_n]]


def build_document_frequency(cheatsheets_folder: str):
    df = {}
    file_contents = {}
    for filename in os.listdir(cheatsheets_folder):
        filepath = os.path.join(cheatsheets_folder, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                raw = f.read()
        except Exception as e:
            continue 
        content = raw.lower().replace("-", " ")
        file_contents[filename] = (raw, content)
        for word in set(re.findall(r'[a-z]+', content)):
            df[word] = df.get(word, 0) + 1
    n_docs = len(file_contents)
    return df, n_docs, file_contents

def find_best_content_match(cwe_description: str, df: dict, n_docs: int, file_contents: dict, min_score: float = 2.0):
    desc_lower = cwe_description.lower().replace("-", " ")
    words = re.findall(r'[a-z]+', desc_lower)
    words = [w for w in words if w not in {"of", "or", "and", "a", "the", "to", "in", "on", "with", "for"}]

    phrases = set()
    for n in (3,2):
        for i in range(len(words) - n + 1):
            phrases.add(" ".join(words[i:i+n]))

    single_keywords = set(w for w in words if len(w) > 3)
    expanded = set(single_keywords)
    for kw in single_keywords:
        if kw in SYNONYM_MAP:
            expanded.update(SYNONYM_MAP[kw])

    best_file, best_score = None, 0.0

    for filename, (raw, content) in file_contents.items():
        phrase_count = sum(content.count(p) for p in phrases)
        if phrase_count > 0:
            score = phrase_count * 10
        else:
            score = 0.0 
            for kw in expanded:
                count = content.count(kw)
                if count > 0:
                    idf = math.log(n_docs / df.get(kw, n_docs))
                    score += count * idf 

        if score > best_score:
            best_score = score 
            best_file = filename 

    if best_score >= min_score:
        return best_file, best_score 
    return None, best_score


if __name__ == "__main__":
    result = parse_owasp_index("CheatSheetSeries/IndexTopTen.md")

    best = find_cheatsheet_with_fallback(
        "Prototype Pollution",
        "A03:2021",
        result,
        "CheatSheetSeries/cheatsheets"
    )
    print("ไฟล์ที่ตรงที่สุด:", best)