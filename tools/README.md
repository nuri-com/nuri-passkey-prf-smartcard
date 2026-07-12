# Pinned Java Card build tool

`ant-javacard-proven.jar` is the exact local `ant-javacard` binary used for the
real-card MuSig2, TOTP, and ETH CAP builds that were preserved in `dist/`.

Its complete corresponding MIT source is included under
`third_party/ant-javacard/`: upstream tag `18.05.01`, commit
`0629c9213b6c00866b70b06a20a18e7ff6fe413a`. The official release asset has
the same hash as this checked-in JAR.

SHA-256:

```text
def557393fd20dbe478a4581c3273222805b9e494836aa8465dfbe0fb9d64cf2  ant-javacard-proven.jar
```

The release build refuses to continue if this hash changes. `ant-javacard` is
an MIT-licensed build tool by Martin Paljak. It is build tooling only and is not
loaded onto the card.
