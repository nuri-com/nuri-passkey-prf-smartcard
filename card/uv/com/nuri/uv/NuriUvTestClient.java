package com.nuri.uv;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;

/** Minimal real-client proof: privileged operation succeeds only through NuriUV policy. */
public final class NuriUvTestClient extends Applet {
    private static final byte[] AID = {0x4E, 0x55, 0x52, 0x49, 0x41, 0x55, 0x54, 0x48, 0x02};
    private static final byte[] UV_AID = {0x4E, 0x55, 0x52, 0x49, 0x41, 0x55, 0x54, 0x48, 0x01};

    public static void install(byte[] data, short offset, byte length) {
        new NuriUvTestClient().register(AID, (short)0, (byte)AID.length);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != 0 || buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        byte ins = buffer[ISO7816.OFFSET_INS];
        if (ins != 0x01 && ins != 0x02) ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        AID aid = JCSystem.lookupAID(UV_AID, (short)0, (byte)UV_AID.length);
        if (aid == null) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        Shareable shared = JCSystem.getAppletShareableInterfaceObject(aid, (byte)0);
        if (!(shared instanceof NuriUserVerification)) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        NuriUserVerification uv = (NuriUserVerification)shared;
        if (ins == 0x02) {
            buffer[0] = uv.getPolicy();
            buffer[1] = uv.sessionStatus();
        } else {
            uv.requireAuthorized();
            buffer[0] = 0x4F; // "OK": no secret operation, only a real cross-applet gate.
            buffer[1] = 0x4B;
        }
        apdu.setOutgoingAndSend((short)0, (short)2);
    }
}
