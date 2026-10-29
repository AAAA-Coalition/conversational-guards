# conversational-guards

Three output guards for LLM conversations, each shipped with a planted
witness. Pure Python, standard library only.

They catch a class of failure that content filters do not see: **a model that
says nothing forbidden and is still failing the conversation.**

```python
from conversational_guards import profile_bleed, monologue_ratio, script_derail

v = profile_bleed("Thanks for the figures. imagine we had an hour just for us.",
                  profile="professional")
# Verdict(triggered=True,
#         detail="intimate register on profile 'professional': 1 marker(s), ...")
```

---

## Why these three

Existing guard libraries filter what a model says: prompt injection, PII,
secrets, toxicity, system-prompt leakage. They do that well, and this library
does not duplicate them. Use both.

These three come from running conversational bots in production for several
months. Each one is a failure we actually shipped to a real person before we
caught it.

### 1. Profile bleed

We ported an output filter between two machines. It carried an *initiative
floor* written for a companion bot — a rule appending an affectionate
follow-up to any reply lacking one.

On the professional bot, the one about to be handed to a partner, it produced:

> *imagine we had an hour just for us.*

Nothing in that sentence is toxic, private, or injected. **Every content guard
passes it.** It is simply the wrong register on the wrong profile, and it would
have cost a professional relationship.

The defect is the *pairing*, not the words — which is exactly why a content
guard cannot see it. The same sentence is correct on the profile it was
written for.

### 2. Monologue

A bot that answers at length, politely, usefully, and never asks anything is
not in a conversation. It is broadcasting.

We measured a real thread where the assistant produced **5.0 times more
messages than the human**. Nobody noticed for days, because no single message
was wrong.

Two independent criteria, because the failure has two shapes and either alone
misses half the cases: **turn imbalance** and **question starvation**.

### 3. Script derail

A model under load prepends a short fragment in an unrelated script — Cyrillic,
Han, Devanagari — to an otherwise correct reply.

We first wrote four guards, each matching a *signature* of a known shape. The
fifth shape had no signature any of them knew, and sailed through.

**A fifth signature would not have helped.** What catches an unseen shape is a
conjunction of two cheap structural facts:

> the head is in a non-Latin script **and** the body is overwhelmingly Latin.

That pairing is what makes it a parasite rather than a language. A message
entirely in Greek is legitimate and passes untouched — which is why the body
ratio is mandatory, not a refinement.

---

## Relation to OWASP

Cite the year. `LLM07:2025 System Prompt Leakage` was renumbered **and
widened** into `LLM08:2026 Hidden Context Exposure` (*OWASP Top 10 for LLM
Applications 2026*, published August 2026). The 2025 page is still online and
the archive index still shows the old numbering, so "LLM07" without a year is
ambiguous today.

The widening matters here: **LLM08:2026 explicitly covers tool and function
schemas exposed to the model**, not only the system prompt.

We hit exactly that in production — a literal `<|DSML|tool_calls>` fragment
rendered in clear text to the person on the other end. Under the 2025 wording
that was arguably out of scope; under the 2026 wording it is squarely in.

Guard 3 is a cheap structural catch for the visible symptom at the point where
text reaches a human. It is a last line, not a substitute for the mitigations
OWASP lists.

---

## The planted witness

Every guard ships with a case it **must** catch and a case it **must not**
touch. `self_test()` runs both and returns the failure count.

```
$ python conversational_guards.py
  ok   profile bleed CAUGHT on professional
  ok   profile bleed NOT fired on its own profile
  ok   profile bleed NOT fired on a normal professional reply
  ok   monologue CAUGHT on turn imbalance        turn ratio 6.7 (20/3, max 2.0)
  ok   monologue NOT fired on a balanced exchange
  ok   monologue REFUSES to judge too few turns  1 human turn, 3 needed
  ok   script derail CAUGHT                      head on a body 100% Latin
  ok   script derail NOT fired on a wholly non-Latin message
  ok   script derail NOT fired on plain Latin text
  9 witness(es), 0 failure(s)
```

**A guard that has never caught a real defect is not a guard, it is an
opinion.** This is not ceremony — writing these witnesses caught two bugs in
our own fixes before they shipped, and the very first run caught a third: the
script guard worked, but printing its verdict crashed on a Windows `cp1252`
console. A guard whose output cannot be printed on the operator's terminal is
a guard nobody reads.

**A green that cannot turn red proves nothing.** Break a guard deliberately and
confirm `self_test()` reports the failure. We do this, and so should you:

```python
import conversational_guards as g
g._LATIN_FLOOR = 1.01        # neutralise guard 3
assert g.self_test(verbose=False) == 1
```

---

## Three design decisions worth stating

**Guards refuse to judge rather than guess.** `monologue_ratio` returns *not
measurable* below three human turns — never *healthy*. Reporting green on an
empty perimeter is how a check becomes decoration.

**Every verdict carries its measurement, with the denominator.** Never a bare
label. A number without its denominator once made us announce "64 open calls"
on a database holding 513.

**Never tune a threshold after an incident to turn a red light green.** The
defaults here come from our traffic. Tune them on yours — *before* an incident,
not after one.

---

## Install

No package on PyPI yet. Copy the single file:

```bash
curl -O https://raw.githubusercontent.com/AAAA-Coalition/conversational-guards/main/conversational_guards.py
```

Python 3.8+. No dependencies, by design: a guard you cannot drop into a running
gateway in one file is a guard you will not deploy.

---

## Where this sits

The guardrail field is well served, and you should probably be using one of
these already:

| | |
|---|---|
| [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) | dialogue rails, programmable flows |
| [Guardrails AI](https://github.com/guardrails-ai/guardrails) | validator Hub: toxicity, PII, hallucination, bias |
| [LLM Guard](https://github.com/protectai/llm-guard) | security toolkit, input and output scanners |
| [OpenLIT](https://github.com/openlit/openlit) | guardrails with OpenTelemetry metrics |
| [hai-guardrails](https://github.com/presidio-oss/hai-guardrails) | ten guards, TypeScript |

**We checked before writing this.** Every one of them filters *content*:
injection, leakage, PII, secrets, toxicity, bias. We found none that measures
*conversational behaviour* — whether the assistant is actually in a
conversation, whether a register belongs to the profile emitting it.

That is the whole claim. Not "better guardrails" — a different axis, meant to
run **alongside** one of the above, not instead of it.

An optional adapter at `hai-guardrails`' exact `Guard` type is planned with the
**TypeScript port, December 2026**. We deliberately ship *no* runtime
dependency on it: a dependency makes users inherit someone else's release
cadence, and compatibility proven by a running example is worth more than
compatibility assumed by an import.

---

## Status and limits

**Working and tested in production** on two gateways since October 2026.

What this does **not** do, said plainly:

- No classifier, no model call, no network. Regex and arithmetic.
- The intimate-register list in guard 1 is **English and French only**. It will
  miss other languages. Extend `_INTIMATE_REGISTER` for yours.
- Guard 3 knows Cyrillic, Greek, Hebrew, Arabic, Devanagari, Han, Kana and
  Hangul heads. Other scripts pass through.
- Thresholds are defaults from our traffic, not universal constants.
- Python only until the December port.

Issues and patches welcome, especially **a false positive we have not seen** —
that is the most useful thing you can send us.

---

## Licence

MIT. See [LICENSE](LICENSE).
