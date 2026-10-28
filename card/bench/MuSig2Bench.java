// SPDX-License-Identifier: MIT
// Throwaway profiling applet. Never installed by a release build.
package nuri.musig2;
import javacard.framework.*;
import javacard.security.*;

/** Public, non-keyed benchmark under the dedicated temporary AID4 only.
 * CLA 80, INS 70, P1 operation, P2 repetitions (1..255); output is 32 bytes.
 * Operations: 0 no-op, 1 RSA init, 2 RSA square, 3 multiply n, 4 multiply p,
 * 5 scalar fold n, 6 field fold p, 7 ECDH scalar one, 8 SHA256, 9 RNG,
 * 10 point validation (fixed public generator, equation plus native ECDH).
 */
public final class MuSig2Bench extends Applet {
    private final RsaMultiply math;
    private final Scalar256 scalar;
    private final byte[] a, b, out, point;
    private final ECPrivateKey key;
    private final KeyAgreement ec;
    private final MessageDigest hash;
    private final RandomData rng;
    public static void install(byte[] data, short off, byte len) {
        new MuSig2Bench().register();
    }
    private MuSig2Bench() {
        math = new RsaMultiply();
        scalar = new Scalar256();
        a = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        b = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        out = JCSystem.makeTransientByteArray((short)65, JCSystem.CLEAR_ON_DESELECT);
        point = new byte[65];
        Util.arrayCopyNonAtomic(NuriMuSig2v019.SECP256K1, (short)128, point, (short)0, (short)65);
        ECPrivateKey candidate;
        try {
            candidate = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, (short)256, false);
        } catch (CryptoException unavailable) {
            candidate = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)256, false);
        }
        key = candidate;
        key.setFieldFP(NuriMuSig2v019.SECP256K1,(short)0,(short)32);
        key.setA(NuriMuSig2v019.SECP256K1,(short)32,(short)32);
        key.setB(NuriMuSig2v019.SECP256K1,(short)64,(short)32);
        key.setR(NuriMuSig2v019.SECP256K1,(short)96,(short)32);
        key.setG(point,(short)0,(short)65);
        key.setK((short)1);
        ec = KeyAgreement.getInstance((byte)6,false);
        hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256,false);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }
    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80 || buf[ISO7816.OFFSET_INS] != (byte)0x70)
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        short op=(short)(buf[ISO7816.OFFSET_P1]&255);
        short count=(short)(buf[ISO7816.OFFSET_P2]&255);
        if(count==0 || op>10) ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        Util.arrayFillNonAtomic(a,(short)0,(short)32,(byte)0xa5);
        Util.arrayFillNonAtomic(b,(short)0,(short)32,(byte)0x5a);
        b[31]=1;
        key.setS(b,(short)31,(short)1);
        ec.init(key);
        for(short i=0;i<count;i++) {
            switch(op) {
                case 0: break;
                case 1: math.benchInit(); break;
                case 2: math.benchSquare(); break;
                case 3: math.multiply(a,(short)0,b,(short)0,out,(short)0,false); break;
                case 4: math.multiply(a,(short)0,b,(short)0,out,(short)0,true); break;
                case 5: math.benchFold(false); break;
                case 6: math.benchFold(true); break;
                case 7: ec.generateSecret(point,(short)0,(short)65,out,(short)0); break;
                case 8: hash.doFinal(a,(short)0,(short)32,out,(short)0); break;
                case 9: rng.generateData(out,(short)0,(short)32); break;
                case 10:
                    scalar.fieldMultiply(point,(short)1,point,(short)1,a,(short)0);
                    scalar.fieldMultiply(a,(short)0,point,(short)1,a,(short)0);
                    Util.arrayFillNonAtomic(b,(short)0,(short)32,(byte)0);
                    b[31]=7;
                    scalar.fieldAdd(a,(short)0,b,(short)0,a,(short)0);
                    scalar.fieldMultiply(point,(short)33,point,(short)33,b,(short)0);
                    short bad=0;
                    for(short j=0;j<32;j++) bad|=(short)(a[j]^b[j]);
                    if(bad!=0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    ec.generateSecret(point,(short)0,(short)65,out,(short)0);
                    bad=0;
                    for(short j=0;j<65;j++) bad|=(short)(point[j]^out[j]);
                    if(bad!=0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    break;
            }
        }
        Util.arrayCopyNonAtomic(out,(short)0,buf,(short)0,(short)32);
        math.clear();
        apdu.setOutgoingAndSend((short)0,(short)32);
    }
}
