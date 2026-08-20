from typing import List, TypedDict

from backend.server_core.workbench.registry import Operation, list_operations

AMBIGUOUS_PRIORITY_THRESHOLD = 500
SCORE_MARGIN = 0.05
MAX_DEPTH_DEFAULT = 8

_COMMON_BIGRAMS = frozenset(
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt "
    "ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma".split()
)


class DecloakStep(TypedDict, total=False):
    operation_id: str
    name: str
    input: str
    output: str


def _bigram_score(text: str) -> float:
    lower = text.lower()
    pairs = [lower[i:i + 2] for i in range(len(lower) - 1)]
    if not pairs:
        return 0.0
    hits = sum(1 for p in pairs if p in _COMMON_BIGRAMS)
    return hits / len(pairs)


def _score(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c != "�" and (c.isprintable() or c in " \t\n\r"))
    printable_ratio = good / len(text)
    words = text.split()
    space_ratio = text.count(" ") / len(text)
    word_bonus = 0.0
    if len(words) >= 2:
        avg_len = sum(len(w) for w in words) / len(words)
        if 2 <= avg_len <= 12:
            word_bonus = 0.15
    control_penalty = sum(1 for c in text if ord(c) < 32 and c not in "\t\n\r") / len(text)
    bigram_bonus = _bigram_score(text) * 0.5
    raw = printable_ratio * 0.5 + space_ratio * 0.1 + word_bonus + bigram_bonus - control_penalty
    return max(0.0, min(1.0, raw))


def _candidate_operations() -> List[Operation]:
    return sorted(
        (op for op in list_operations() if op.decloak_try is not None),
        key=lambda op: op.decloak_priority,
    )


def run_decloak(input_text: str, max_depth: int = MAX_DEPTH_DEFAULT) -> dict:
    ops = _candidate_operations()
    terminal_ops = [op for op in ops if op.decloak_terminal]
    layer_ops = [op for op in ops if not op.decloak_terminal]

    current = input_text
    steps: List[DecloakStep] = []
    seen = {current}
    stopped_reason = "plaintext"

    for _ in range(max_depth):
        best = None
        ambiguous_best = None
        ambiguous_best_score = -1.0
        for op in layer_ops:
            if op.decloak_try is None:
                continue
            candidate = op.decloak_try(current)
            if candidate is None or candidate == current:
                continue
            if op.decloak_priority >= AMBIGUOUS_PRIORITY_THRESHOLD:
                if " " not in candidate:
                    continue
                candidate_score = _score(candidate)
                if candidate_score > ambiguous_best_score:
                    ambiguous_best_score = candidate_score
                    ambiguous_best = (op, candidate)
                continue
            best = (op, candidate)
            break

        if best is None and ambiguous_best is not None:
            if ambiguous_best_score > _score(current) + SCORE_MARGIN:
                best = ambiguous_best

        if best is not None:
            op, candidate = best
            steps.append({"operation_id": op.id, "name": op.name, "input": current, "output": candidate})
            if candidate in seen:
                stopped_reason = "cycle"
                break
            seen.add(candidate)
            current = candidate
            continue

        matched_terminal = False
        for op in terminal_ops:
            if op.decloak_try is None:
                continue
            result = op.decloak_try(current)
            if result is not None:
                steps.append({"operation_id": op.id, "name": op.name, "input": current, "output": result})
                current = result
                stopped_reason = "terminal"
                matched_terminal = True
                break
        if matched_terminal:
            break

        stopped_reason = "plaintext"
        break
    else:
        stopped_reason = "max_depth"

    return {"steps": steps, "output": current, "stopped_reason": stopped_reason}
