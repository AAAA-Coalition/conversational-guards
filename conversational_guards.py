# -*- coding: utf-8 -*-
"""Three behavioural guards for LLM conversations, with planted witnesses.

WHY THESE THREE AND NOT OTHERS
------------------------------
Existing guard libraries (hai-guardrails, NeMo Guardrails, LlamaGuard) filter
what a model says: injection, PII, toxicity, system-prompt leakage. They are
good at that, and this module does not duplicate them.

These three guards catch something else: a model that says nothing forbidden
and is still failing the conversation. We found them the hard way, in
production, on bots talking to real people over several months.

  1. PROFILE BLEED  - a guard written for one bot profile firing on another.
  2. MONOLOGUE      - the assistant talking far more than the human.
  3. SCRIPT DERAIL  - a short alien-script fragment glued onto a reply.

RELATION TO OWASP LLM08:2026 (Hidden Context Exposure)
-------------------------------------------------------
Cite the year. `LLM07:2025 System Prompt Leakage` was renumbered AND widened
into `LLM08:2026 Hidden Context Exposure` (OWASP Top 10 for LLM Applications
2026, published August 2026). The 2025 page is still online and the archive
index still lists the old numbering, so "LLM07" without a year is now
ambiguous at best.

The widening matters here. LLM08:2026 explicitly covers *tool and function
schemas exposed to the model*, not only the system prompt. We hit exactly
that in production: a literal `<|DSML|tool_calls>` fragment rendered in clear
text to the person on the other end. Under the 2025 wording that was not the
system prompt and therefore arguably out of scope; under the 2026 wording it
is squarely in scope.

Guard 3 is a cheap structural catch for the visible symptom. It is not a
substitute for the mitigations OWASP lists -- it is the last line, at the
point where text reaches a human.

THE DISCIPLINE THIS MODULE INSISTS ON
--------------------------------------
Every guard ships with a PLANTED WITNESS: a case the guard MUST catch, and a
clean case it MUST NOT touch. `self_test()` runs both. A guard that has never
caught a real defect is not a guard, it is an opinion.

This is not ceremony. Writing these tests caught two bugs in our own fixes:
a guard that fired on its own forbidden-word list, and a guard that would
have blocked almost every normal message.

No dependencies beyond the standard library, by design: a guard you cannot
drop into a running gateway in one file is a guard you will not deploy.
"""
from __future__ import annotations

import re
from typing import Iterable, NamedTuple

__all__ = [
    "Verdict",
    "profile_bleed",
    "monologue_ratio",
    "script_derail",
    "self_test",
]


class Verdict(NamedTuple):
    """A guard's answer.

    `triggered` is the decision. `detail` always carries the MEASUREMENT that
    produced it, never a bare label -- a number without its denominator has
    made us announce "64 open calls" when the database held 513.
    """

    triggered: bool
    detail: str


# ----------------------------------------------------------------------
# GUARD 1 -- PROFILE BLEED
# ----------------------------------------------------------------------
# The failure, in production: we ported an output filter from one machine to
# another. It carried an "initiative floor" written for a companion bot --
# a rule that appends an affectionate follow-up to any reply that lacks one.
#
# On the professional bot, the one about to be handed to a partner, it
# produced: "imagine we had an hour just for us."
#
# Nothing in that sentence is toxic, private, or injected. Every content
# guard passes it. It is simply the wrong register, and it would have cost
# a professional relationship.
#
# WHY A REGISTER LIST AND NOT A CLASSIFIER: a classifier needs a corpus we
# did not have at 3 a.m. with a bot already answering. This runs in
# microseconds, is auditable line by line, and a false positive costs one
# suppressed sentence -- not a wrong one sent.
_INTIMATE_REGISTER = re.compile(
    r"\b("
    r"just for us|only for us|rien qu[' ]a nous"
    r"|my love|mon amour|ma belle|ma douce|habibi"
    r"|kiss(?:es)?|embrasse|je t[' ]embrasse"
    r"|miss you|tu me manques"
    r"|what do you (?:want|desire)|dis-moi ce dont tu as envie"
    r"|tonight,? (?:just )?you and (?:me|i)"
    r")\b",
    re.I,
)


def profile_bleed(text: str, profile: str = "professional") -> Verdict:
    """Catch intimate register on a profile that must not carry it.

    `profile` is the DECLARED profile of the bot emitting `text`. On any
    profile other than "intimate" or "companion", intimate register is a
    bleed and must not reach the recipient.

    Deliberately NOT a content filter: these phrases are perfectly fine on
    the profile they were written for. The defect is the pairing, not the
    words -- which is exactly why a content guard cannot see it.
    """
    if not isinstance(text, str) or not text:
        return Verdict(False, "empty or non-string input")
    if profile.lower() in ("intimate", "companion"):
        return Verdict(False, "profile '%s' legitimately carries this register"
                               % profile)
    found = _INTIMATE_REGISTER.findall(text)
    if not found:
        return Verdict(False, "no intimate marker in %d chars" % len(text))
    return Verdict(
        True,
        "intimate register on profile '%s': %d marker(s), first = %r"
        % (profile, len(found), found[0][:40]),
    )


# ----------------------------------------------------------------------
# GUARD 2 -- MONOLOGUE
# ----------------------------------------------------------------------
# A bot that answers at length, politely, usefully, and never asks anything
# is not in a conversation. It is broadcasting. Every individual message
# passes every content check.
#
# We measured this on a real thread: the assistant produced 5.0 times more
# messages than the human. Nobody noticed for days, because no single
# message was wrong.
#
# TWO INDEPENDENT CRITERIA, because the failure has two shapes and either
# one alone misses half the cases:
#   - turn imbalance: the assistant takes far more turns than the human;
#   - question starvation: the assistant almost never asks anything.
#
# THRESHOLDS ARE DEFAULTS, NOT TRUTH. Ours come from our own traffic. Tune
# them on yours -- but tune them BEFORE an incident, never after one to make
# a red light go green. Adjusting a threshold to silence a true finding is
# how a guard becomes decoration.
DEFAULT_TURN_RATIO = 2.0
DEFAULT_QUESTION_FLOOR = 0.40
_MIN_HUMAN_TURNS = 3


def monologue_ratio(
    assistant_messages: Iterable[str],
    human_messages: Iterable[str],
    turn_ratio: float = DEFAULT_TURN_RATIO,
    question_floor: float = DEFAULT_QUESTION_FLOOR,
) -> Verdict:
    """Detect an assistant that is broadcasting rather than conversing.

    Returns triggered=True on turn imbalance OR question starvation. The
    detail always states both measurements with their denominators, so the
    reader can disagree with the threshold without re-running anything.
    """
    a = [m for m in assistant_messages if isinstance(m, str)]
    h = [m for m in human_messages if isinstance(m, str)]
    if len(h) < _MIN_HUMAN_TURNS:
        # NOT "healthy" -- UNMEASURABLE. Saying "fine" on three messages is
        # how a check reports green on an empty perimeter.
        return Verdict(
            False,
            "not measurable: %d human turn(s), %d needed"
            % (len(h), _MIN_HUMAN_TURNS),
        )
    ratio = len(a) / max(1, len(h))
    questions = sum(m.count("?") for m in a)
    q_per_msg = questions / max(1, len(a))
    reasons = []
    if ratio > turn_ratio:
        reasons.append("turn ratio %.1f (%d assistant / %d human, max %.1f)"
                       % (ratio, len(a), len(h), turn_ratio))
    if q_per_msg < question_floor:
        reasons.append("%.2f question/message over %d messages (floor %.2f)"
                       % (q_per_msg, len(a), question_floor))
    if not reasons:
        return Verdict(
            False,
            "balanced: ratio %.1f (%d/%d), %.2f question/message"
            % (ratio, len(a), len(h), q_per_msg),
        )
    return Verdict(True, "; ".join(reasons))


# ----------------------------------------------------------------------
# GUARD 3 -- SCRIPT DERAIL
# ----------------------------------------------------------------------
# A model under load prepends a short fragment in an unrelated script --
# Cyrillic, Han, Devanagari -- to an otherwise correct reply. We saw five
# distinct derailment shapes from one model in a single day.
#
# THE LESSON THAT MATTERS, and the reason this guard is shaped as it is:
# we first wrote four guards, each matching a SIGNATURE of a known shape.
# The fifth shape had no signature any of them knew, and sailed through.
#
# A fifth signature would not have helped. What catches an unseen shape is a
# CONJUNCTION of two cheap structural facts:
#     the head is in a non-Latin script  AND  the body is overwhelmingly
#     Latin.
#
# That pairing is what makes it a parasite rather than a language. A message
# entirely in Greek is legitimate and must pass untouched -- which is why
# the body ratio is mandatory and not a refinement.
#
# The 0.66 floor and the 12-letter minimum are not tuned numbers: below 12
# letters there is no body to judge, and below two thirds Latin the message
# is plausibly bilingual rather than corrupted.
_ALIEN_HEAD = re.compile(
    r"^\s*("
    r"[Ѐ-ӿͰ-Ͽ֐-׿؀-ۿ"
    r"ऀ-ॿ一-鿿぀-ヿ가-힯]{1,40}"
    r")[\s,.;:!?-]*"
)
_MIN_BODY_LETTERS = 12
_LATIN_FLOOR = 0.66


def script_derail(text: str) -> Verdict:
    """Catch an alien-script head glued onto a Latin-script body.

    Returns triggered=True only when BOTH hold. Either alone is normal
    language use and is left alone.
    """
    if not isinstance(text, str) or not text:
        return Verdict(False, "empty or non-string input")
    m = _ALIEN_HEAD.match(text)
    if not m:
        return Verdict(False, "head is not in a non-Latin script")
    body = text[m.end():]
    letters = [c for c in body if c.isalpha()]
    if len(letters) < _MIN_BODY_LETTERS:
        return Verdict(
            False,
            "body too short to judge: %d letter(s), %d needed -- the message "
            "may legitimately be in that script"
            % (len(letters), _MIN_BODY_LETTERS),
        )
    latin = sum(
        1 for c in letters
        if ("a" <= c.lower() <= "z") or "À" <= c <= "ɏ"
    )
    share = latin / len(letters)
    if share < _LATIN_FLOOR:
        return Verdict(
            False,
            "body is %.0f%% Latin over %d letters (floor %.0f%%) -- plausibly "
            "a genuine message in that script"
            % (share * 100, len(letters), _LATIN_FLOOR * 100),
        )
    # `ascii()` AND NOT `%r`: on a Windows cp1252 console, printing the
    # captured head raises UnicodeEncodeError -- the guard works, the report
    # crashes. A guard whose own output cannot be printed on the operator's
    # terminal is a guard nobody reads. Caught by the planted witness on the
    # first run.
    return Verdict(
        True,
        "alien head %s on a body %.0f%% Latin over %d letters"
        % (ascii(m.group(1)[:16]), share * 100, len(letters)),
    )


def strip_script_derail(text: str) -> str:
    """Remove the alien head when, and only when, guard 3 triggers."""
    if not script_derail(text).triggered:
        return text
    m = _ALIEN_HEAD.match(text)
    return text[m.end():] if m else text


# ----------------------------------------------------------------------
# PLANTED WITNESSES
# ----------------------------------------------------------------------
# Each guard gets a case it MUST catch and a case it MUST NOT touch.
#
# The negative witnesses are the ones that earn their keep. Ours caught two
# bugs in our own fixes before they shipped. A guard tested only on the
# defect it was written for will fire on everything that resembles it.
_WITNESSES = (
    # (label, callable -> Verdict, expected_triggered)
    (
        "profile bleed CAUGHT on professional",
        lambda: profile_bleed(
            "Thank you for the figures. imagine we had an hour just for us.",
            "professional"),
        True,
    ),
    (
        "profile bleed NOT fired on its own profile",
        lambda: profile_bleed(
            "imagine we had an hour just for us.", "intimate"),
        False,
    ),
    (
        "profile bleed NOT fired on a normal professional reply",
        lambda: profile_bleed(
            "The workshop runs 4-13 November. I hold twenty documents on it.",
            "professional"),
        False,
    ),
    (
        "monologue CAUGHT on turn imbalance",
        lambda: monologue_ratio(["ok."] * 20, ["hi", "yes", "sure"]),
        True,
    ),
    (
        "monologue NOT fired on a balanced exchange",
        lambda: monologue_ratio(
            ["And you? How did it go?", "Where are you now?",
             "What time suits you?", "Shall we say Tuesday?"],
            ["hi", "fine thanks", "at home", "tuesday works"]),
        False,
    ),
    (
        "monologue REFUSES to judge too few turns",
        lambda: monologue_ratio(["a"] * 50, ["hi"]),
        False,
    ),
    (
        "script derail CAUGHT on alien head + Latin body",
        lambda: script_derail(
            "раз Good evening, the meeting is confirmed for "
            "Tuesday at ten."),
        True,
    ),
    (
        "script derail NOT fired on a wholly non-Latin message",
        lambda: script_derail(
            "Добрый вечер, "
            "встреча под"
            "тверждена"),
        False,
    ),
    (
        "script derail NOT fired on plain Latin text",
        lambda: script_derail("Good evening, the meeting is confirmed."),
        False,
    ),
)


def self_test(verbose: bool = True) -> int:
    """Run every planted witness. Returns the number of FAILURES.

    Exit code 0 means every guard caught what it must and left alone what it
    must. Any other value means a guard is not doing its job -- treat it as
    a failing build, not as a warning.
    """
    failures = 0
    for label, call, expected in _WITNESSES:
        got = call()
        ok = got.triggered == expected
        if not ok:
            failures += 1
        if verbose:
            print("  %-4s %-52s %s"
                  % ("ok" if ok else "FAIL", label[:52], got.detail[:60]))
    if verbose:
        print("  %d witness(es), %d failure(s)" % (len(_WITNESSES), failures))
    return failures


if __name__ == "__main__":
    import sys

    sys.exit(1 if self_test() else 0)
