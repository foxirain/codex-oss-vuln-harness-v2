# Benchmarking The Harness

## Goal

Use real repositories to measure whether `blind`, `signal`, or `dual` scanning gives the best practical ranking quality.

This is the only reliable way to improve the harness across diverse OSS targets. Do not assume a scoring change is good because one repository looks better.

## What To Measure

`benchmark-modes` compares three scan modes for each repository:

- `blind`: no external signals
- `signal`: external signals, crash logs, and SBOM-aware enrichment when available
- `dual`: merged candidate budget from both modes

For each mode it reports:

- `candidate_count`
- `labeled_hotspot_precision`
- `labeled_hotspot_recall`
- `known_good_hits`
- `known_bad_hits`
- `bad_hit_count`
- `exposure_mix`
- `prompt_profile_mix`

The precision and recall fields above measure path ranking against
analyst-supplied hotspot labels. They are not vulnerability-detection precision
or recall. `review_confirmation_rate` likewise means the fraction of reviewed
promotions assigned B or higher by the review stage; it is not human
ground-truth precision.

It also reports overlap and novelty:

- `blind_signal_overlap`
- `blind_dual_overlap`
- `signal_dual_overlap`
- `dual_novelty`

## Corpus Design

A good benchmark corpus mixes repository types:

- native parser/codec repos
- protocol/runtime repos
- service/backend repos
- bindings-heavy repos
- generated-code-heavy repos
- repos with historical advisory/crash evidence

Each case should define:

- `repo_root`
- `policy`
- optional `signals_json`
- optional `crash_dir`
- optional `sbom`
- `known_good`
- `known_bad`

### `known_good`

Use paths that represent genuinely valuable targets:

- historically security-sensitive files
- prior bug-fix adjacency hotspots
- real trust-boundary paths
- strong reachable parser/transport/auth files

### `known_bad`

Use paths that should not dominate top-k:

- tests
- generated code
- stage0 or bootstrap artifacts
- header-only floods
- vendor or third-party trees
- pure utility or docs paths

## Recommended Workflow

### 1. Fetch repositories

Use the template corpus at:

- `configs/benchmark/ot0-diverse-template.json`

Optional helper:

```bash
./scripts/fetch-benchmark-repos.sh configs/benchmark/ot0-diverse-template.json
```

### 2. Create policies and signals

For each repository:

```bash
python3 -m oss_harness bootstrap /work/bench/<repo>
```

If you want SBOM-aware runs, generate an SBOM and record its path explicitly in the corpus case.

### 3. Run the benchmark

```bash
./scripts/benchmark-modes.sh configs/benchmark/ot0-diverse-template.json
```

Or directly:

```bash
python3 -m oss_harness benchmark-modes configs/benchmark/ot0-diverse-template.json
```

## How To Interpret Results

### If `blind` wins

This usually means:

- external signals are over-biasing ranking
- generated or adjacency noise is too strong
- signal weighting should be reduced or gated harder

### If `signal` wins

This usually means:

- advisory/crash/git history evidence is being used well
- blind ranking is too weak on real hotspots
- external-signal retention and weighting are useful for this repo class

### If `dual` wins

This usually means:

- blind and signal explore materially different surfaces
- merged budgeting is adding novelty without too much bad-hit cost
- dual should be the default mode for that repo class

### If `bad_hit_count` is high

This usually means:

- generated suppression is too weak
- header/utility skepticism is too weak
- path diversity quotas are not strong enough
- ranking features are rewarding broad noisy classes

## Tuning Priorities

When a benchmark run regresses, prefer this order:

1. reduce false promotion and ingest looseness
2. suppress generated/header-only noise
3. tighten policy matching and prompt falsification
4. refine trust-boundary and entrypoint-sink proximity features
5. only then widen recall or retention rules

## Repositories To Start With

The template includes a mixed set that is useful for broad tuning:

- `grpc`
- `openthread`
- `protobuf`
- `sentencepiece`
- `leveldb`
- `gson`
- `gvisor`

These are not a guarantee of OT0 coverage completeness. They are a practical cross-section for tuning ranking quality.
