# Vendored Nuri FIDO2 source snapshot

This directory is based on Nuri fork commit
`4f318197cc08f316ce784a89bdf29dc73cca7fcf` (`working fido2 nuri`). Its parent
is upstream FIDO2Applet v2.0.5 commit
`0194107d9648577379058b59843504924b546514`.
It is a deliberately reduced/modified snapshot, not a byte-exact upstream copy.

```mermaid
flowchart LR
  U[Upstream MIT FIDO2] --> N[Nuri fork source]
  N --> P[Packaging exclusions and documentation changes]
  P --> B[External Gradle and SDK]
  B --> C[CAP and simulator builds]
```

The source is the base used for `FIDO2.cap` and `FIDO2-up.cap`. The two
repository-root applet patches are applied only inside `.build/`:

1. `0001-prf-on-by-default.patch`
2. `0002-advertise-user-presence.patch`

## Deliberate deviations and exclusions

- The upstream `sdks` Git submodule is not redistributed. The release builder
  checks out the public `oracle_javacard_sdks` repository at the exact submodule
  commit `e2df471e04d86f33de69a947f44766fbef1d9d69` and verifies it before compiling.
  The SDK retains its own licence; it is not covered by the applet MIT grant.
- The Apache-2.0 Gradle wrapper launchers `gradlew` and `gradlew.bat`,
  `gradle/wrapper/gradle-wrapper.jar` and the unused
  `gradle/wrapper/gradle-wrapper.properties` are removed. Install Gradle **8.2 or
  newer** separately and verify `gradle --version`. The old wrapper selected
  8.2; use that version for the closest historical toolchain match. Root build
  and simulator scripts check the minimum version and use `gradle` from PATH,
  or the executable selected by `GRADLE_BIN`. The release provenance records
  the actual version; newer toolchain reproducibility must be verified.
- `mds.json` is excluded pending separate rights/provenance confirmation for its
  metadata, embedded icon and certificate. It is not needed by the Java/CAP
  compilation. This exclusion does not change the applet's licence.
- `README.md` build instructions and Python test build-error messages are
  updated to use installed `gradle` instead of the removed wrapper.
- The simulator-only `JPype1` pin is updated from historical 1.5.0 to 1.7.1
  so the Python-to-JVM bridge supports current Python 3.14. This does not enter
  or change the Java Card CAP build.

The retained applet source is **MIT**, copyright (c) 2022 Bryan Jacobs. The
original `LICENSE` is preserved here. External build tools and dependencies
retain their own terms; no FIDO2 applet rewrite or relicence is claimed.
See the repository-root `THIRD_PARTY_NOTICES.md` for the mixed-repository map.

Historical non-build material is excluded from this public snapshot. This
packaging description does not attest that old history or release copies are
free of confidential/vendor material.
