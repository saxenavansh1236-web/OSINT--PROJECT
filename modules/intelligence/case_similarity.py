"""
modules/intelligence/case_similarity.py
-----------------------------------------
Finds other cases in the system that resemble a given case, using
tags, target infrastructure overlap (IP/subdomains/whois org), and
shared threat indicators from scan_data — no external ML dependency.

Also provides a lightweight "Notes Intelligence" summary: turns a raw
notes list into counts/highlights for the case intelligence panel.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class SimilarCase(object):
    case_id: int
    title: str
    target: str
    score: float                 # 0-1
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "target": self.target,
            "score": round(self.score, 3),
            "score_pct": round(self.score * 100),
            "reasons": self.reasons,
        }


def _as_dict(case: Any) -> Dict[str, Any]:
    if isinstance(case, dict):
        return case
    if hasattr(case, "to_dict"):
        return case.to_dict()
    if hasattr(case, "__dict__"):
        return dict(vars(case))
    return {}


def _tags_of(case: Dict[str, Any]) -> set:
    tags = case.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    return set(t.lower() for t in tags)


def _domain_root(target: str) -> str:
    target = (target or "").lower().strip()
    parts = target.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return target


def _scan_indicators(case: Dict[str, Any]) -> Dict[str, Any]:
    scan = case.get("scan_data") or {}
    whois = scan.get("whois") or {}
    return {
        "ip": scan.get("ip"),
        "org": (whois.get("org") if isinstance(whois, dict) else None),
        "subs": set((s if isinstance(s, str) else s.get("host", ""))
                     for s in (scan.get("subs") or [])),
        "breach_names": set(
            (b.get("name") or b.get("breach_name") or "")
            for b in (scan.get("breach") or []) if isinstance(b, dict)
        ),
    }


def compute_similarity(case_a: Dict[str, Any], case_b: Dict[str, Any]) -> SimilarCase:
    a, b = _as_dict(case_a), _as_dict(case_b)

    reasons = []
    score = 0.0

    tags_a, tags_b = _tags_of(a), _tags_of(b)
    if tags_a and tags_b:
        overlap = tags_a & tags_b
        if overlap:
            jaccard = len(overlap) / len(tags_a | tags_b)
            score += jaccard * 0.35
            reasons.append(f"shared tags: {', '.join(sorted(overlap))}")

    root_a, root_b = _domain_root(a.get("target", "")), _domain_root(b.get("target", ""))
    if root_a and root_a == root_b:
        score += 0.25
        reasons.append(f"same root domain ({root_a})")

    ind_a, ind_b = _scan_indicators(a), _scan_indicators(b)

    if ind_a["ip"] and ind_a["ip"] == ind_b["ip"] and ind_a["ip"] != "Not found":
        score += 0.2
        reasons.append(f"same resolved IP ({ind_a['ip']})")

    if ind_a["org"] and ind_a["org"] == ind_b["org"]:
        score += 0.1
        reasons.append(f"same WHOIS organization ({ind_a['org']})")

    sub_overlap = ind_a["subs"] & ind_b["subs"]
    sub_overlap.discard("")
    if sub_overlap:
        score += min(len(sub_overlap) * 0.05, 0.15)
        reasons.append(f"{len(sub_overlap)} shared subdomain(s)")

    breach_overlap = ind_a["breach_names"] & ind_b["breach_names"]
    breach_overlap.discard("")
    if breach_overlap:
        score += min(len(breach_overlap) * 0.05, 0.15)
        reasons.append(f"shared breach source(s): {', '.join(sorted(breach_overlap))}")

    score = min(score, 1.0)

    return SimilarCase(
        case_id=b.get("id") or b.get("case_id"),
        title=b.get("title", b.get("target", "Unknown case")),
        target=b.get("target", ""),
        score=round(score, 3),
        reasons=reasons,
    )


def find_similar_cases(target_case: Dict[str, Any], all_cases: List[Any],
                        threshold: float = 0.15, top_n: int = 5) -> List[SimilarCase]:
    try:
        target_case = _as_dict(target_case)
        target_id = target_case.get("id") or target_case.get("case_id")

        results = []
        for c in (all_cases or []):
            try:
                cd = _as_dict(c)
                if (cd.get("id") or cd.get("case_id")) == target_id:
                    continue
                sim = compute_similarity(target_case, cd)
                if sim.score >= threshold:
                    results.append(sim)
            except Exception:
                continue

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:top_n]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Notes Intelligence — summarizes an investigator notes list
# ---------------------------------------------------------------------------

def summarize_notes(notes: List[Any]) -> Dict[str, Any]:
    """
    Lightweight structural summary of a case's investigator notes —
    counts and most recent activity, used in the intelligence panel.
    No content generation/paraphrasing of note text; just metadata.
    """
    items = []
    for n in notes or []:
        nd = _as_dict(n)
        items.append({
            "author": nd.get("author", "unknown"),
            "created_at": nd.get("created_at") or nd.get("timestamp"),
            "content": nd.get("content", ""),
        })

    return {
        "total_notes": len(items),
        "authors": sorted(set(i["author"] for i in items)),
        "latest": items[-1] if items else None,
    }