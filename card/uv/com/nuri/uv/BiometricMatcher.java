package com.nuri.uv;

/** Vendor-neutral on-card biometric backend. No images or templates cross this API. */
interface BiometricMatcher {
    short MATCH_OK = 0;
    short MATCH_FAILED = 1;
    short MATCH_TIMEOUT = 2;
    short MATCH_ERROR = 3;

    boolean available();
    byte templateBitmap();
    short match();
    /** One enrollment touch; returns current touch, or a negative error. */
    short enrollStep(byte touch);
    byte enrollmentTouches();
}
