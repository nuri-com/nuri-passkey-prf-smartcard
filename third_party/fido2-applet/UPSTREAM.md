# Vendored Nuri FIDO2 source snapshot

This directory is the build-critical source snapshot at Nuri fork commit
`4f318197cc08f316ce784a89bdf29dc73cca7fcf` (`working fido2 nuri`). Its parent
is upstream FIDO2Applet v2.0.5 commit
`0194107d9648577379058b59843504924b546514`.

The snapshot is the base used by the real-card-proven `FIDO2.cap` and
`FIDO2-up.cap`. Nuri changes remain reviewable as the two repository-root
patches and are applied only inside `.build/`:

1. `0001-prf-on-by-default.patch`
2. `0002-advertise-user-presence.patch`

The upstream `sdks` Git submodule is intentionally not redistributed here.
The release builder checks out the public `oracle_javacard_sdks` repository at
the exact submodule commit
`e2df471e04d86f33de69a947f44766fbef1d9d69` and verifies it before compiling.

License: MIT. The original `LICENSE` is preserved in this directory.

The simulator-only `JPype1` pin is updated from the historical 1.5.0 to 1.7.1
so the Python-to-JVM bridge supports current Python 3.14. This does not enter or
change the Java Card CAP build.

The historical worktree also contained confidential IDEX integration documents,
an IDEX service JAR, and an unrelated GlobalPlatformPro binary. They are not
required by this FIDO2 build and are intentionally excluded from the public
snapshot and release.
