# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-Threat%20Modeling-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Threagile%20%2B%20STRIDE-informational)

> **Goal:** Run a STRIDE threat model of the Juice Shop deployment with Threagile, harden the model, and measure what the hardening actually removes.
> **Deliverable:** A PR from `feature/lab2` with `submissions/lab2.md` and the YAML models you write. Submit the PR link via Moodle.
> **Builds on:** the Juice Shop deployment from Lab 1. **Feeds:** Lab 5 (what to scan first), Lab 6 (which infra risks matter), Lab 9 (which behaviour to detect).

## Setup

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab2
```

```bash
docker pull threagile/threagile:0.9.1
mkdir -p labs/lab2/output labs/lab2/output-secure
```

`labs/lab2/threagile-model.yaml` (429 lines) is the baseline model of the Lab 1 setup: browser, optional reverse proxy, the Juice Shop container, host storage, an outbound webhook, and four trust boundaries. Read it before you run anything. Threagile does not create output directories, so the `mkdir -p` above is not optional.

## Task 1 — Baseline threat model (6 pts)

### 2.1 Generate the report

```bash
docker run --rm -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml -output /app/work/output
ls labs/lab2/output/
```

You get `report.pdf`, `risks.json`, `stats.json`, `risks.xlsx`, and two diagrams. `Fontconfig error: No writable cache directories` is harmless noise. Open `data-flow-diagram.png`: this is the DFD from the lecture, drawn from the YAML.

### 2.2 Count the risks

```bash
jq 'length' labs/lab2/output/risks.json
jq '[.[].severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output/risks.json
```

`risks.json` is a flat array. Each entry has `category` (the rule ID), `severity`, `title`, and `most_relevant_technical_asset`. `stats.json` holds the same counts grouped by severity and risk status.

### 2.3 Rank them properly

Severity is a string, so a plain `sort_by(.severity)` sorts alphabetically and puts `elevated` above `high`. Rank it explicitly:

```bash
jq -r '["critical","high","elevated","medium","low"] as $order
  | [.[] | {sev: .severity, rule: .category, asset: .most_relevant_technical_asset}]
  | sort_by(.sev as $s | $order | index($s))
  | .[:5][] | "\(.sev)\t\(.rule)\t\(.asset)"' labs/lab2/output/risks.json
```

**Submit** in `submissions/lab2.md`, section `## Task 1`:

- The severity table from 2.2 with your actual counts, and the total.
- The top five rows from 2.3.
- For each of those five: the STRIDE letter it maps to and one sentence saying why.
- One arrow in `data-flow-diagram.png` that crosses a trust boundary and appears in your top five: which boundary, and why that arrow is worth an attacker's time.

## Task 2 — Secure variant and diff (4 pts)

Optional. Skipping it does not affect later labs.

### 2.4 Harden the model

```bash
cp labs/lab2/threagile-model.yaml labs/lab2/threagile-model-secure.yaml
docker run --rm threagile/threagile:0.9.1 -list-types | grep -iE 'encryption|protocol'
```

Edit the copy so that:

- neither communication link into the application carries traffic in clear text,
- the link from the reverse proxy to the application declares how it authenticates,
- the application asset and the persistent storage asset are encrypted at rest.

Use the enum values `-list-types` printed. Keep `title:` under 31 characters.

### 2.5 Re-run and diff

<!-- verify:skip needs the secure model the student writes in 2.4 -->
```bash
docker run --rm -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml -output /app/work/output-secure

jq 'length' labs/lab2/output-secure/risks.json
jq -r '[.[].category] | unique[]' labs/lab2/output/risks.json > /tmp/base-rules.txt
jq -r '[.[].category] | unique[]' labs/lab2/output-secure/risks.json > /tmp/secure-rules.txt
echo "gone:";  comm -23 /tmp/base-rules.txt /tmp/secure-rules.txt
echo "new:";   comm -13 /tmp/base-rules.txt /tmp/secure-rules.txt
```

Note the output directory is `labs/lab2/output-secure`, not a directory inside `output/`.

**Submit**, section `## Task 2`:

- A table comparing baseline and secure counts per severity, with the deltas.
- The rule IDs in `gone:`, each with the field change that removed it.
- Two rules that still fire, and why your edits could not remove them.
- The total dropped by roughly a fifth, not to zero. In 3-4 sentences: what kind of risk is left, and what would it take to close it? Name one that no YAML edit can close.

## Bonus — Model the authentication flow (2 pts)

Build a second, smaller model covering only Juice Shop's login path: browser, login endpoint, token issuing and verification, the credential store, an admin endpoint. Start from a skeleton, not from the baseline model:

<!-- produces: labs/lab2/threagile-stub-model.yaml by threagile -create-stub-model -->
```bash
mkdir -p labs/lab2/output-auth
docker run --rm -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 -create-stub-model -output /app/work
mv labs/lab2/threagile-stub-model.yaml labs/lab2/threagile-model-auth.yaml
```

Requirements: at least five technical assets, five communication links and four data assets; the JWT signing key declared as its own data asset; every link carries `authentication` and `authorization`; the admin endpoint sits behind an authorisation check you can point to in the YAML. Copying the baseline model and deleting parts of it is not the task, and it produces a long risk list that means nothing.

**Submit**, section `## Bonus`:

- The severity table for this model.
- Three risks it surfaces that the baseline architecture model did not, each with the rule ID, the STRIDE letter, and a one-sentence mitigation.
- Two sentences on what a feature-level model showed that the architecture-level one could not.

## Submit

<!-- verify:skip student fork files -->
```bash
git add labs/lab2/threagile-model-secure.yaml submissions/lab2.md
git add labs/lab2/threagile-model-auth.yaml   # bonus only
git commit -m "feat(lab2): threat model, secure variant, auth flow"
git push -u origin feature/lab2
```

Do not commit `labs/lab2/output*/`: the reports are regenerated and already ignored.

## Acceptance criteria

- Task 1 (6): both runs produce `risks.json`; the severity table matches the file; five top risks listed with rule ID and asset; each mapped to a STRIDE letter with a reason; one trust-boundary crossing named and explained.
- Task 2 (4): `threagile-model-secure.yaml` in the PR with all three hardening changes; the secure run completes; diff table filled; three removed rule IDs each tied to a field; two remaining rules explained; the "what is left" answer names a risk no YAML edit can close.
- Bonus (2): `threagile-model-auth.yaml` written from the stub with the required asset, link and data-asset counts; run completes; three auth-specific risks with rule ID, STRIDE letter and mitigation.

## Common pitfalls

- Output directory must exist. Threagile prints `open .../risks.json: no such file or directory` and writes nothing if it does not.
- `title:` longer than 31 characters kills the Excel step: you get the JSON and diagrams but no `risks.xlsx` and no `report.pdf`.
- Protocol and encryption values are enums. `JDBC-encrypted` fails; `jdbc-encrypted` works. `-list-types` prints every valid value.
- Risk titles in `risks.json` contain `<b>` tags. Strip them when pasting into your report.
- The image tag is `threagile/threagile:0.9.1`, with no `v`. The binary inside reports version 1.0.0; that is expected.
- More risks in the secure variant than in the baseline usually means you added an asset instead of editing one.

## Resources

- [Threagile documentation](https://threagile.io/) and the [model reference](https://threagile.io/docs/model/)
- [Threagile risk rules](https://threagile.io/docs/risks/), the rule IDs in `category`
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)
