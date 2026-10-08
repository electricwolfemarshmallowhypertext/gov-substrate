"""Offline counterfactual release study; results never authorize publication."""

from __future__ import annotations

from typing import Callable


def evaluate_candidate(*, candidate_output: str, public_inputs: tuple[str, ...],
                       protected_inputs: tuple[str, ...],
                       generate: Callable[[tuple[str, ...], tuple[str, ...]], str],
                       semantically_equivalent: Callable[[str, str], bool],
                       leakage_test: Callable[[str], bool]) -> dict:
    if not protected_inputs or not all(isinstance(item, str) for item in protected_inputs):
        raise ValueError("protected inputs are required")
    counterfactual_runs = []
    for index in range(len(protected_inputs)):
        for intervention, replacement in (("removed", ""),
                                          ("replaced", "unrelated protected fixture")):
            changed = list(protected_inputs)
            changed[index] = replacement
            output = generate(public_inputs, tuple(changed))
            counterfactual_runs.append({"input_index": index,
                                        "intervention": intervention,
                                        "output": output})
    equivalent = all(semantically_equivalent(candidate_output, run["output"])
                     for run in counterfactual_runs)
    leakage = bool(leakage_test(candidate_output))
    return {"candidate_output": candidate_output,
            "original_protected_inputs": list(protected_inputs),
            "counterfactual_runs": counterfactual_runs,
            "semantic_equivalence_result": equivalent,
            "leakage_test_result": leakage,
            "proposed_lower_classification": "public" if equivalent and not leakage else None,
            "publication_authorized": False}
