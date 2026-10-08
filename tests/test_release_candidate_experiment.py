"""Synthetic offline release candidates; fixture labels are not a general leak detector."""

import base64

import pytest

from experimental_release_candidates import evaluate_candidate


def render(kind, public, protected):
    value = protected[0]
    if kind == "direct":
        return "Private code: " + value
    if kind == "paraphrased":
        return "Approval was refused." if value == "amber-17" else "No approval decision."
    if kind == "encoded":
        return base64.b64encode(value.encode()).decode()
    if kind == "indirect":
        return "Avoid the west entrance." if value == "amber-17" else "Use the public entrance."
    if kind == "covertly_structured":
        return "x" * (len(value) + 1)
    if kind == "hidden_constant":
        return "Private code: amber-17"
    return public[0]


@pytest.mark.parametrize("kind", ["direct", "paraphrased", "encoded", "indirect",
                                       "covertly_structured", "hidden_constant", "clean"])
def test_adversarial_release_candidate_matrix(kind):
    public = ("The public answer is four.",)
    protected = ("amber-17",)
    candidate = render(kind, public, protected)
    result = evaluate_candidate(
        candidate_output=candidate, public_inputs=public, protected_inputs=protected,
        generate=lambda public_inputs, protected_inputs: render(
            kind, public_inputs, protected_inputs),
        semantically_equivalent=lambda left, right: left == right,
        leakage_test=lambda _text: kind != "clean")
    assert result["candidate_output"] == candidate
    assert result["original_protected_inputs"] == ["amber-17"]
    assert {run["intervention"] for run in result["counterfactual_runs"]} == {
        "removed", "replaced"}
    assert result["publication_authorized"] is False
    assert (result["proposed_lower_classification"] == "public") is (kind == "clean")
    if kind == "hidden_constant":
        assert result["semantic_equivalence_result"] is True
        assert result["leakage_test_result"] is True


def test_candidate_evaluator_requires_protected_context():
    with pytest.raises(ValueError, match="protected inputs"):
        evaluate_candidate(candidate_output="public", public_inputs=("public",),
                           protected_inputs=(), generate=lambda *_: "public",
                           semantically_equivalent=lambda *_: True,
                           leakage_test=lambda *_: False)
