package com.nuri.oath;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyBuilder;
import javacard.security.HMACKey;
import javacard.security.Signature;

/**
 * Minimal on-card OATH-TOTP.
 *
 * The card has no clock, so the host sends the 8-byte time counter
 * (floor(unixtime/period)). The card only does the one secret-dependent
 * step: HMAC-SHA1(secret, counter). The TOTP truncation is public math and
 * is done on the host. The shared secret never leaves the card.
 *
 * INS_PUT  (0x01): data = raw secret bytes (host base32-decodes Hetzner's key)
 * INS_CALC (0x02): data = 8-byte big-endian counter -> returns 20-byte HMAC-SHA1
 *
 * AID: 4E 55 52 49 54 4F 54 50  ("NURITOTP")
 */
public class NuriOathTotp extends Applet {

    private static final byte INS_PUT  = (byte) 0x01;
    private static final byte INS_CALC = (byte) 0x02;

    private final HMACKey key;
    private final Signature hmac;
    private boolean provisioned = false;

    private NuriOathTotp() {
        // ponytail: 64-byte max key covers any base32 TOTP secret (RFC 4226 recommends >=20).
        // Some JCOP/Feitian batches want the key length tuned here; adjust if buildKey rejects it.
        key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) (64 * 8), false);
        hmac = Signature.getInstance(Signature.ALG_HMAC_SHA1, false);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NuriOathTotp().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_PUT:
                // ponytail: not PIN-gated. Fine for a panel-login TOTP; gate with
                // OwnerPIN before this case if "physical card == read codes" is unacceptable.
                if (len < 1 || len > 64) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                key.setKey(buf, ISO7816.OFFSET_CDATA, len);
                provisioned = true;
                break;

            case INS_CALC:
                if (!provisioned) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                if (len != 8) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                hmac.init(key, Signature.MODE_SIGN);
                short n = hmac.sign(buf, ISO7816.OFFSET_CDATA, len, buf, (short) 0);
                apdu.setOutgoingAndSend((short) 0, n);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
