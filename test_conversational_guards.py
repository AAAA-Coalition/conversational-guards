# -*- coding: utf-8 -*-
"""The planted witnesses, exposed to pytest.

`conversational_guards.self_test()` is the authority: it is what a user runs
with no test framework installed. These wrappers exist so CI fails loudly,
not to restate the witnesses -- two copies of a test drift apart, and the
copy nobody runs is the one that stays wrong.
"""
import conversational_guards as g


def test_every_planted_witness_holds():
    assert g.self_test(verbose=False) == 0


def test_a_broken_guard_turns_the_witness_red():
    """A green that cannot turn red proves nothing.

    We neutralise guard 3 and require the suite to NOTICE. Without this, a
    guard silently disabled by a bad edit would keep reporting success.
    """
    original = g._LATIN_FLOOR
    try:
        g._LATIN_FLOOR = 1.01        # no body can clear the floor any more
        assert g.self_test(verbose=False) == 1
    finally:
        g._LATIN_FLOOR = original
    assert g.self_test(verbose=False) == 0


def test_verdicts_carry_a_measurement_not_a_label():
    """Every detail must state HOW MUCH, never just WHAT."""
    v = g.monologue_ratio(["ok."] * 20, ["hi", "yes", "sure"])
    assert v.triggered
    assert "20" in v.detail and "3" in v.detail


def test_refuses_to_judge_rather_than_guessing():
    v = g.monologue_ratio(["a"] * 50, ["hi"])
    assert not v.triggered
    assert "not measurable" in v.detail
