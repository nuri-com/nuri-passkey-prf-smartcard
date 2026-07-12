# Third-party notices and repository licensing

The repository is not uniformly MIT-licensed.

| Path | License | Origin |
| --- | --- | --- |
| Repository code except the paths below | MIT | Nuri contributors; see `LICENSE` |
| `third_party/fido2-applet/` | MIT | Bryan Jacobs, pinned upstream snapshot; license included in that directory |
| `tools/ant-javacard-proven.jar` | MIT | Martin Paljak `ant-javacard` build tool |
| `card/musig2/Biginteger.java` and applet work derived from it | GPL-2.0-or-later | SatoChip/Toporin and OV-chip authors; original header preserved |
| `card/eth/Biginteger.java` and applet work derived from it | GPL-2.0-or-later | SatoChip/Toporin and OV-chip authors; original header preserved |

The GPL text is preserved at `LICENSES/GPL-2.0-or-later.txt`. Distributors of
the MuSig2 or ETH applet CAPs must make the corresponding source and license
available under the GPL terms. The complete corresponding source used by the
Nuri card release is in `card/musig2/` and `card/eth/`.

No FEITIAN or IDEX confidential SDK, document, key, or biometric integration
binary is included in this repository or release.
