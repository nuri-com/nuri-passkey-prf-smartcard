package com.nuri.uv;

/** Scripted sensor for reader-free policy tests. */
final class MatcherFactory {
    static byte initialBitmap() { return bitmap; }
    static byte bitmap;
    static short matchResult;
    static short enrollResult;

    static BiometricMatcher create() {
        return new BiometricMatcher() {
            public boolean available() { return true; }
            public byte templateBitmap() { return bitmap; }
            public short match() { return matchResult; }
            public short enrollStep(byte touch) {
                if (enrollResult != 0) return enrollResult;
                bitmap = touch == enrollmentTouches() ? (byte)1 : bitmap;
                return touch;
            }
            public byte enrollmentTouches() { return 12; }
        };
    }
}
