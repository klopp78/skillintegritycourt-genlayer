# SkillIntegrityCourt for GenLayer

`SkillIntegrityCourt` is a reusable GenLayer Intelligent Contract that produces a consensus receipt before an AI agent installs a skill, plugin, or framework extension.

## The decision it makes

`assess_skill()` receives one exact skill name, version, declared capabilities, and two to five public sources. Validators independently render the full sources and return one of:

- `allow`: the exact skill, version, and declared capabilities are authenticated and risk is low or medium;
- `hold`: the evidence establishes a concrete high-risk or critical concern;
- `inconclusive`: sources are unavailable, incomplete, conflicting, or do not bind the exact requested artifact.

The contract is a decision primitive, not an installer or payment relay. A caller can require a stored `allow` receipt before it installs an agent skill.

## Integrity model

- full rendered snapshots are SHA-256 committed, never truncated;
- source URLs use canonical host and registrable-domain identities, so `www`, sibling subdomains, and mirrors do not count as independent sources;
- every consequential verdict field and every snapshot commitment is recomputed in `gl.vm.run_nondet_unsafe` by validators;
- each accepted write has a deterministic receipt ID and append-only record;
- canonical JSON plus length-prefixed SHA-256 inputs prevent ambiguous composite commitments;
- malformed model output, prompt injection, mismatched versions, omitted capabilities, or inaccessible sources fail closed to `inconclusive`.

## Contract API

```python
assess_skill(skill_name, version, declared_capabilities, source_urls) -> str
get_receipt(receipt_id) -> str
get_latest_receipt_id() -> str
get_receipt_count() -> u64
list_receipt_ids() -> str
```

## Verification

```powershell
python -m unittest discover -s tests -v
```

## Suggested evidence

Use a canonical package manifest or registry record plus an independent upstream release or capability document. The contract requires two distinct registrable domains.

## Studio deployment

- Contract: `0xE9165c748219beAEE5D03C6813f174e11f57406f`
- Explorer: https://explorer-studio.genlayer.com/address/0xE9165c748219beAEE5D03C6813f174e11f57406f

The deployed Studio source matches `contracts/skill_integrity_court.py` at commit `300e5c6`.
