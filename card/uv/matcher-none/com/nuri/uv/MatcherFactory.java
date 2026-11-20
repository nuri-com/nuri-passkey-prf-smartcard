package com.nuri.uv;

/** Default PIN-only build. Private vendor builds replace this source directory. */
final class MatcherFactory {
    static byte initialBitmap() { return 0; }
    static BiometricMatcher create() {
        return new BiometricMatcher() {
            public boolean available() { return false; }
            public byte templateBitmap() { return 0; }
            public short match() { return MATCH_ERROR; }
            public short enrollStep(byte touch) { return -1; }
            public byte enrollmentTouches() { return 0; }
        };
    }
}
