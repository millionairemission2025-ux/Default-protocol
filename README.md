# DEFAULT Protocol (v1.0)
### The Minimal Open Standard for Digital Decision Certification.

DEFAULT is a neutral, minimal protocol designed to certify that a digital decision was made with explicit consent, at a specific time, within a specific context.

## Why DEFAULT?
Digital disputes often arise from ambiguity: *"I didn't agree"*, *"It wasn't clear"*, *"The terms changed"*. 
DEFAULT eliminates this by creating a standardized, 6-field cryptographic record of any digital agreement.

## The Record Structure
A DEFAULT record consists of exactly 6 fields:

1. **decision_id**: Unique identifier for the decision.
2. **subject_id**: Identifier of the decider (can be anonymized).
3. **values_hash**: SHA-256 hash of the declared values/terms.
4. **context_hash**: SHA-256 hash of the environment/context.
5. **timestamp**: ISO 8601 UTC synchronized time.
6. **signatures**: An array of digital signatures (Issuer, Timestamp Authority, etc.).

## Core Principles
- **Minimalist**: Only 6 fields. No bloat.
- **Neutral**: Does not decide what is right; only certifies what was agreed.
- **Verifiable**: Anyone can re-hash the data to verify integrity.
- **Open Source**: Released under CC0 (Public Domain). No licenses, no lock-in.

## License
This project is dedicated to the public domain under CC0.
