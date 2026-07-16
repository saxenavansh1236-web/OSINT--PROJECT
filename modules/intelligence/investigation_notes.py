"""
investigation_notes.py
-----------------------
Case Similarity + Notes engine, and a combined report that ties together
Confidence Score + Risk Analysis + Case Similarity + Notes.

Case Similarity uses a simple, dependency-free weighted Jaccard/overlap
score across tags, keywords, and structured fields — no external NLP
libraries required. Swap in embeddings later if you want semantic
similarity; the interface (`similarity(case_a, case_b)`) stays the same.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from confidence_score import compute_confidence, ConfidenceResult


# ---------------------------------------------------------------------------
# Case Similarity
# ---------------------------------------------------------------------------

def _set_overlap(a: List[str], b: List[str]) -> float:
    sa, sb = set(x.lower().strip() for x in a), set(x.lower().strip() for x in b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)  # Jaccard


@dataclass
class SimilarityResult:
    case_id_a: str
    case_id_b: str
    score: float                # 0-1
    matched_tags: List[str] = field(default_factory=list)
    matched_keywords: List[str] = field(default_factory=list)

    def summary(self) -> str:
        pct = round(self.score * 100)
        return f"Similarity({self.case_id_a} ↔ {self.case_id_b}): {pct}%"


def compute_similarity(case_a: Dict[str, Any], case_b: Dict[str, Any]) -> SimilarityResult:
    """
    Weighted overlap across:
      tags       0.40
      keywords   0.30
      location   0.15  (exact match bonus)
      method     0.15  (exact match bonus, e.g. "modus operandi")
    """
    tags_a, tags_b = case_a.get("tags", []), case_b.get("tags", [])
    kw_a, kw_b = case_a.get("keywords", []), case_b.get("keywords", [])

    tag_sim = _set_overlap(tags_a, tags_b)
    kw_sim = _set_overlap(kw_a, kw_b)

    location_match = 1.0 if (
        case_a.get("location") and
        case_a.get("location", "").lower() == case_b.get("location", "").lower()
    ) else 0.0

    method_match = 1.0 if (
        case_a.get("method") and
        case_a.get("method", "").lower() == case_b.get("method", "").lower()
    ) else 0.0

    score = (tag_sim * 0.40) + (kw_sim * 0.30) + (location_match * 0.15) + (method_match * 0.15)

    matched_tags = list(set(t.lower() for t in tags_a) & set(t.lower() for t in tags_b))
    matched_keywords = list(set(k.lower() for k in kw_a) & set(k.lower() for k in kw_b))

    return SimilarityResult(
        case_id_a=case_a.get("id", "A"),
        case_id_b=case_b.get("id", "B"),
        score=round(score, 3),
        matched_tags=matched_tags,
        matched_keywords=matched_keywords,
    )


def find_similar_cases(target: Dict[str, Any], candidates: List[Dict[str, Any]],
                        threshold: float = 0.3, top_n: int = 5) -> List[SimilarityResult]:
    """Return the top_n most similar cases to `target` from `candidates`, above threshold."""
    results = [
        compute_similarity(target, c) for c in candidates
        if c.get("id") != target.get("id")
    ]
    results = [r for r in results if r.score >= threshold]
    results.sort(key=lambda r: r.score, reverse=True)
    return results[:top_n]


# ---------------------------------------------------------------------------
# Investigation Notes
# ---------------------------------------------------------------------------

@dataclass
class Note:
    author: str
    text: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    tags: List[str] = field(default_factory=list)

    def format(self) -> str:
        tag_str = f" [{', '.join(self.tags)}]" if self.tags else ""
        return f"[{self.timestamp}] {self.author}: {self.text}{tag_str}"


class NotesLog:
    """Append-only notes log for a case."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self._notes: List[Note] = []

    def add(self, author: str, text: str, tags: List[str] = None) -> Note:
        note = Note(author=author, text=text, tags=tags or [])
        self._notes.append(note)
        return note

    def all(self) -> List[Note]:
        return list(self._notes)

    def filter_by_tag(self, tag: str) -> List[Note]:
        tag = tag.lower()
        return [n for n in self._notes if tag in (t.lower() for t in n.tags)]

    def render(self) -> str:
        if not self._notes:
            return f"No notes recorded for case {self.case_id}."
        header = f"Notes — Case {self.case_id} ({len(self._notes)} entries)"
        lines = [header, "-" * len(header)]
        lines.extend(n.format() for n in self._notes)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Combined Report
# ---------------------------------------------------------------------------

def generate_report(case: Dict[str, Any], candidates: List[Dict[str, Any]] = None,
                     notes_log: NotesLog = None) -> str:
    """
    Produces the combined intelligence report:
      Confidence Score
      Risk Analysis
      Case Similarity
      Notes
    """
    confidence: ConfidenceResult = compute_confidence(case)

    lines = []
    lines.append(f"=== Investigation Intelligence Report — Case {case.get('id', 'UNKNOWN')} ===")
    lines.append("")
    lines.append("Confidence Score")
    lines.append(f"  Confidence: {confidence.score}%")
    lines.append("")
    lines.append("Risk Analysis")
    lines.append(f"  Risk: {confidence.risk_level}")
    if confidence.warnings:
        lines.append("  Flags:")
        for w in confidence.warnings:
            lines.append(f"    - {w}")
    lines.append("")

    lines.append("Case Similarity")
    if candidates:
        matches = find_similar_cases(case, candidates)
        if matches:
            for m in matches:
                lines.append(f"  {m.summary()}")
                if m.matched_tags:
                    lines.append(f"    matched tags: {', '.join(m.matched_tags)}")
                if m.matched_keywords:
                    lines.append(f"    matched keywords: {', '.join(m.matched_keywords)}")
        else:
            lines.append("  No similar cases found above threshold.")
    else:
        lines.append("  No candidate cases supplied.")
    lines.append("")

    lines.append("Notes")
    if notes_log and notes_log.all():
        lines.append(notes_log.render())
    else:
        lines.append("  No notes recorded.")

    return "\n".join(lines)


if __name__ == "__main__":
    case_a = {
        "id": "CASE-1001",
        "evidence": [{"type": "document", "verified": True, "weight": 0.9}],
        "witnesses": [{"reliability": 0.8, "consistent": True}],
        "timeline_complete": True,
        "corroboration_count": 4,
        "contradictions": 1,
        "digital_trail": 0.7,
        "prior_flags": 1,
        "tags": ["fraud", "wire-transfer", "corporate"],
        "keywords": ["invoice", "shell company", "offshore"],
        "location": "Delhi",
        "method": "invoice fraud",
    }
    case_b = {
        "id": "CASE-1002",
        "tags": ["fraud", "corporate", "embezzlement"],
        "keywords": ["invoice", "offshore", "kickback"],
        "location": "Delhi",
        "method": "invoice fraud",
    }
    case_c = {
        "id": "CASE-1003",
        "tags": ["theft", "residential"],
        "keywords": ["burglary"],
        "location": "Mumbai",
        "method": "break-in",
    }

    notes = NotesLog(case_a["id"])
    notes.add("Investigator R. Sharma", "Cross-referenced bank statements with invoice dates.",
              tags=["evidence"])
    notes.add("Investigator R. Sharma", "Witness statement partially contradicts timeline on day 3.",
              tags=["contradiction", "witness"])

    print(generate_report(case_a, candidates=[case_b, case_c], notes_log=notes))