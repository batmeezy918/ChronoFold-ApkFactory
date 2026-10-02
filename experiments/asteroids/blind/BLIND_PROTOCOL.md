# Asteroids EXE -> APK Blind Protocol

Target: newagebegins/asteroids v1.0.

Allowed before freeze:
- Asteroids.exe release artifact.
- Generic PE format knowledge.
- LIEF, pefile, binutils and other explicitly declared static-analysis tools.
- Public documentation of the tools.

Forbidden before freeze:
- Asteroids.apk.
- Asteroids source tree.
- Android project files.
- Any generated artifact derived from the withheld APK/source.

Required records:
1. SHA-256 of the EXE.
2. Tool versions.
3. Extraction commands.
4. CF-IR.
5. Quotient/invariant declarations.
6. Unresolved gap ledger.
7. Twin build manifest.
8. Frozen hash of all blind inputs.

Only after the twin is frozen may the reference APK be introduced for differential testing.

Finite differential agreement is evidence, not a universal proof.
