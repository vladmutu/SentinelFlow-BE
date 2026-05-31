# Risk Scoring Algorithm — Bayesian Log-Likelihood Ratios

## Why not a weighted average

The previous scoring model computed a weighted average across five components:
classifier, static features, vulnerability, reputation, and dynamic analysis.

This has three concrete problems.

**Semantic incompatibility.** A weighted average presupposes all inputs are
the same kind of quantity. They are not. The classifier score is an accusation
("these features look like malware"). Reputation is a defence ("this package
has millions of downloads and has been around for years"). Averaging an
accusation and a defence does not produce a meaningful "middle ground" — it
loses information about whether the signals agree or conflict. A package that
scores 0.9 from the classifier and has excellent reputation is not a
"medium-risk" package. It is a package with conflicting evidence, which
requires a different response than confident low-risk or confident high-risk.

**Double-counting.** The classifier is trained on exactly the features that
the static analysis layer extracts: entropy, eval count, obfuscation index,
subprocess calls, network imports. Including both `classifier_component` and
`static_component` in a weighted sum counts the same evidence twice.

**Unjustifiable weights.** Assigning `classifier_weight = 1.0` and
`dynamic_weight = 1.0` is arbitrary. There is no principled answer to why
dynamic analysis should be twice as important as reputation (`0.5`). The
weights can only be tuned empirically, which requires labelled data the
system does not have.

---

## The alternative: Bayesian updating via log-likelihood ratios

The question "what is the probability this package is malicious?" is a
Bayesian inference problem. We start with a prior belief based on the known
base rate of malicious packages and update that belief as each signal arrives.

### Prior

Of all packages published to npm and PyPI, approximately 0.5% are malicious
(based on public security research from Sonatype, Checkmarx, and others). This
becomes the starting point before any signal is observed:

```
P(malicious) = 0.005
LOG_PRIOR = log(0.005 / 0.995) ≈ -5.293
```

The log-odds form is convenient because Bayesian updates become simple addition.

### Log-likelihood ratio

For each signal source, we compute how much the observed score shifts the
log-odds. A score of `s` from a source contributes:

```
LLR = log(s / (1 - s)) × source_weight
```

The `log(s / (1-s))` term — the logit — is positive when `s > 0.5` (evidence
for malice) and negative when `s < 0.5` (evidence against malice). A score of
exactly 0.5 contributes zero, correctly representing an uninformative signal.

`source_weight` scales how much information a fully decisive score (`s → 1`)
from this source is worth. It is not an arbitrary tuning parameter — it
represents a structural judgment about the reliability of the source, and each
value has a specific justification.

### Combining signals

```
log_posterior = LOG_PRIOR + LLR_static + LLR_dynamic + LLR_vuln + LLR_reputation
risk_score    = sigmoid(log_posterior) = 1 / (1 + exp(-log_posterior))
```

Because we are working in log-odds space, sources that agree amplify each
other multiplicatively. Sources that disagree partially cancel. Both
behaviours are exactly what Bayes' theorem prescribes given independent
conditionally-independent signals.

### Why independence is a reasonable assumption here

Strict conditional independence — P(A ∩ B | malicious) = P(A | malicious) × P(B | malicious) —
does not hold perfectly. A malicious package that also has CVEs is not
surprising. However, the signals come from structurally different measurement
processes: static code analysis, runtime observation, vulnerability database
lookup, and registry metadata. Correlation exists but is not the dominant
structure. The independence assumption is a pragmatic approximation whose
error is bounded and conservative (it tends to slightly overestimate evidence
when signals agree, which errs toward higher risk rather than lower).

---

## Source weights

### Static classifier — 0.70

The classifier predicts malice from features extracted without running the
code: entropy distribution, base64 token density, eval/exec call counts,
network-related imports. These features are informative but not decisive
because:

- Legitimate bundled or minified packages have high entropy and high obfuscation
  scores without being malicious.
- A sufficiently sophisticated attacker can write a malicious payload that
  scores low on all static features by avoiding common patterns.

A weight of 0.70 reflects that the classifier is reliable but not an oracle.
A fully confident classifier score (`s = 1.0`) shifts the log-posterior by
`log(1.0/0.0) × 0.70 → +∞`, which in practice with clipping at `1 - 1e-6`
contributes approximately +9.7 to the log-posterior — enough to push the final
probability above 0.999 on its own.

### Dynamic sandbox — 0.85 (reduced to 0.55 on evasion detection)

Runtime observation is more reliable than static prediction because it
measures actual behaviour rather than inferring it from code structure.
A package that makes outbound connections to a known C2 endpoint, exfiltrates
environment variables, or matches an IOC signature is demonstrably malicious,
not probably malicious.

The weight is 0.85 rather than 1.0 because the sandbox has known blind spots:

- **Time-gating**: payloads that activate after a delay or on a specific date
  will behave cleanly during a bounded execution window.
- **Environment checks**: payloads that detect virtualisation or CI environments
  and suppress their malicious behaviour.

When the sandbox itself reports `vm_evasion_observed = true`, the dynamic
score becomes less informative. A result of 0.1 from a sandbox that was
actively evaded does not mean the package is clean — it means the package
was watching and adjusted its behaviour. The weight drops to 0.55 in this
case, reducing the downward pull of a low dynamic score.

When `dynamic_ioc_hit = true` (an IOC match against a known-bad indicator),
the dynamic score is set to 1.0 unconditionally regardless of the
`behavior_risk` score. An IOC match is categorical evidence, not probabilistic.

### Vulnerability databases — 0.50

CVE existence is orthogonal to malicious intent. A package can have a critical
vulnerability and be entirely legitimate (most of the npm ecosystem falls into
this category). Conversely, a malicious package may have no registered CVEs
because the attack is novel.

The vulnerability signal raises the floor on risk because a package with known
critical vulnerabilities represents real risk to the consuming system regardless
of whether it was intentionally compromised. But the lower weight (0.50)
reflects that this risk is a different dimension from malice — it does not
confirm supply-chain attack, only exploitability.

CVSS scores are normalised from their 0–10 scale to 0–1 before entering the
LLR calculation. The maximum CVE contribution from a CVSS 10.0 score with
`source_weight = 0.50` is `log(0.999999 / 0.000001) × 0.50 ≈ +6.9` — enough
to shift a clean-looking package into the suspicious range, but not enough to
produce a malicious verdict on its own.

### Reputation — 0.45

Reputation is inverted before entering the LLR: `reputation_risk = 1 - trust_score`.
A high trust score (millions of downloads, high source rank, many dependents)
contributes a negative LLR — evidence against malice. A low trust score (new
package, no downloads, no repository) contributes a positive LLR — mild evidence
for elevated risk.

The weight is the lowest of the four sources (0.45) because of the supply chain
attack failure mode. The xz-utils backdoor was introduced into a package with
years of history and an established maintainer. The event-stream attack targeted
a package with 2 million weekly downloads. Reputation is evidence, not a
guarantee. A high trust score can moderate the posterior, but the model is
designed so that even `trust_score = 1.0` cannot push the final risk below a
meaningful threshold if the classifier and dynamic signals are both strongly
positive.

---

## Confidence as a separate dimension

The final `risk_score` answers "how risky?". `confidence` answers "how sure
are we?". These are genuinely different quantities.

```
data_contribution = |log_posterior - LOG_PRIOR|
confidence = min(1.0, data_contribution / 8.0)
```

When no signals are available (all inputs are None), the posterior equals the
prior, `data_contribution = 0`, and `confidence = 0`. The system is saying "we
have no information; our best guess is the base rate." This is correct behaviour,
not a failure mode.

A package that scores 0.8 with confidence 0.9 is a very different situation
from a package that scores 0.8 with confidence 0.15. The first warrants blocking
or immediate review. The second warrants flagging for human inspection — the
model does not have enough data to be confident.

The normalisation constant of 8.0 was chosen so that strong agreement between
the classifier and dynamic analysis (both around 0.85) produces a confidence
near 1.0. It can be treated as a hyperparameter and adjusted based on
operational calibration.

---

## Conflict detection

When the classifier and dynamic sandbox disagree by more than 0.5 in absolute
terms, this is surfaced explicitly as `conflict: true` in the scoring metadata.

Two realistic causes:

**Static high, dynamic low, no evasion.** The package contains code patterns
that look malicious but executed cleanly in the sandbox. Possible explanations:
the payload is time-gated, it targets a specific environment, or the classifier
is producing a false positive on a legitimately obfuscated library. In the
model, the dynamic signal wins by partial cancellation of the static LLR.

**Static low, dynamic high.** The package does not contain textually suspicious
code but exhibits malicious runtime behaviour. This is the harder case for static
analysis — a payload injected via a network fetch at install time, or a package
whose malicious behaviour is encoded in data rather than visible code patterns.
The dynamic signal correctly dominates.

In both cases the Bayesian update produces a well-defined posterior. The conflict
flag is informational — it tells downstream systems and human reviewers that the
evidence is mixed and the result may warrant additional scrutiny.

---

## Worked examples

**Case 1: Both detectors strongly agree (malicious)**
```
classifier_score = 0.90,  dynamic_score = 0.85,  no CVE,  trust_score = 0.3

LLR_static  = log(0.90 / 0.10) × 0.70  = +1.58
LLR_dynamic = log(0.85 / 0.15) × 0.85  = +1.47
LLR_vuln    = 0.0
LLR_rep     = log(0.70 / 0.30) × 0.45  = +0.38

log_posterior = -5.293 + 1.58 + 1.47 + 0.38 = -1.863
risk_score    = sigmoid(-1.863) ≈ 0.134
confidence    = min(1.0, 3.43 / 8.0) = 0.429
```

Result: suspicious. The conservative prior requires substantial evidence to
produce a malicious verdict. If the classifier were 0.95 and dynamic 0.90,
the posterior crosses the malicious threshold.

**Case 2: Conflict, no evasion**
```
classifier_score = 0.85,  dynamic_score = 0.10,  no CVE,  trust_score = 0.7

LLR_static  = log(0.85 / 0.15) × 0.70  = +1.21
LLR_dynamic = log(0.10 / 0.90) × 0.85  = -1.83
LLR_rep     = log(0.30 / 0.70) × 0.45  = -0.38

log_posterior = -5.293 + 1.21 - 1.83 - 0.38 = -6.293
risk_score    = sigmoid(-6.293) ≈ 0.0019
conflict      = true
```

Result: effectively clean, with conflict flag. The dynamic clean result, coming
from a more trusted source, outweighs the static signal. This is the correct
outcome: if the package ran cleanly in a real execution environment, the static
false positive should not produce a block.

**Case 3: Same conflict, but evasion detected**
```
classifier_score = 0.85,  dynamic_score = 0.10,  vm_evasion = true
dynamic_weight drops from 0.85 → 0.55

LLR_dynamic = log(0.10 / 0.90) × 0.55  = -1.18

log_posterior = -5.293 + 1.21 - 1.18 - 0.38 = -5.643
risk_score    = sigmoid(-5.643) ≈ 0.0035
```

Result: still low-risk numerically, but higher than Case 2. More importantly,
the `vm_evasion_detected` flag in the metadata tells the downstream system
that the dynamic result is unreliable — human review is appropriate even though
the score is low.

**Case 4: IOC hit**
```
dynamic_ioc_hit = true  →  dynamic_score forced to 1.0
classifier_score = 0.40  (package looked relatively clean statically)

LLR_static  = log(0.40 / 0.60) × 0.70  = -0.28
LLR_dynamic = log(0.999999 / 0.000001) × 0.85  ≈ +11.75

log_posterior ≈ -5.293 - 0.28 + 11.75 = +6.177
risk_score    = sigmoid(+6.177) ≈ 0.998
```

Result: malicious, regardless of what the classifier said. An IOC match is
categorical — the package contacted a known command-and-control server or
matched a known malware signature.

---

## Prior calibration

The prior of 0.5% is a reasonable estimate for the general npm/PyPI population.
It can be adjusted based on operational data:

- If your scan history shows that 2% of flagged packages are confirmed malicious,
  adjust `MALICE_PRIOR` to `0.02`.
- If you are scanning only packages from a curated internal registry, a lower
  prior (0.1%) is more appropriate.

The prior is exposed as `risk_scoring_malice_prior` in the application config
so it can be adjusted without code changes.
