// SPDX-License-Identifier: MIT
// Independently authored from 2ab = (a+b)^2 - a^2 - b^2.
package nuri.musig2;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

/** Exact 256-bit multiplication using three unreduced RSA squares.
 * The 768-bit modulus is 2^768-1; inputs have at most 257 bits, so
 * their squares are strictly below the modulus. Exponent two is public.
 * Unsupported providers fail installation closed, never silently downgrade.
 */
final class RsaMultiply {
    private final RSAPublicKey key;
    private final Cipher rsa;
    private final byte[] input;
    private final byte[] squares;
    private final byte[] work;
    private static final byte[] TWO = { 2 };
    RsaMultiply() {
        input = JCSystem.makeTransientByteArray((short)96, JCSystem.CLEAR_ON_DESELECT);
        squares = JCSystem.makeTransientByteArray((short)288, JCSystem.CLEAR_ON_DESELECT);
        work = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
        key = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)768, false);
        Util.arrayFillNonAtomic(input, (short)0, (short)96, (byte)0xff);
        key.setModulus(input, (short)0, (short)96);
        key.setExponent(TWO, (short)0, (short)1);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        // Exercise the exact provider path, including reduction, before install.
        clear();
        input[95] = 3;
        square((short)0);
        short bad = 0;
        for (short i=0; i<95; i++) bad |= squares[i];
        if (bad != 0 || squares[95] != 9) javacard.framework.ISOException.throwIt((short)0x6f31);
        clear();
    }
    private void square(short offset) {
        rsa.init(key, Cipher.MODE_ENCRYPT);
        if (rsa.doFinal(input, (short)0, (short)96, squares, offset) != 96)
            javacard.framework.ISOException.throwIt((short)0x6f32);
    }
    void multiply(byte[] a, short ao, byte[] b, short bo, byte[] out, short oo, boolean field) {
        try {
            Util.arrayCopyNonAtomic(a, ao, input, (short)64, (short)32);
            square((short)0);
            Util.arrayCopyNonAtomic(b, bo, input, (short)64, (short)32);
            square((short)96);
            short carry=0;
            for (short i=31; i>=0; i--) {
                short v=(short)((a[(short)(ao+i)]&255)+(b[(short)(bo+i)]&255)+carry);
                input[(short)(64+i)]=(byte)v; carry=(short)(v>>8);
            }
            input[63]=(byte)carry;
            square((short)192);
            subtract((short)0); subtract((short)96);
            carry=0;
            for(short i=0;i<96;i++) {
                short v=(short)(squares[(short)(192+i)]&255);
                squares[(short)(192+i)]=(byte)((v>>1)|(carry<<7)); carry=(short)(v&1);
            }
            for(short i=0;i<64;i++) work[i]=squares[(short)(287-i)];
            fold((short)32, field); fold(field ? (short)5 : (short)17, field);
            fold((short)2, field); fold((short)1, field); fold((short)1, field);
            // Result is below 2^256. One subtraction suffices for either modulus.
            short borrow=0;
            for(short i=0;i<32;i++) {
                short modulus=(short)(255-complement(i,field));
                // modulus = 2^256-c: byte zero adds the two's-complement one.
                if(i==0) modulus++;
                short v=(short)((work[i]&255)-modulus-borrow);
                work[(short)(64+i)]=(byte)v; borrow=(short)((v>>15)&1);
            }
            short mask=(short)(borrow-1);
            for(short i=0;i<32;i++) out[(short)(oo+31-i)]=(byte)((work[i]&~mask)|(work[(short)(64+i)]&mask));
        } finally { clear(); }
    }
    // c = 2^256 - modulus, little endian. Stored independently of GPL code.
    private static final byte[] CN = { (byte)0xbf,(byte)0xbe,(byte)0xc9,0x2f,0x73,(byte)0xa1,0x2d,0x40,(byte)0xc4,0x5f,(byte)0xb7,0x50,0x19,0x23,0x51,0x45,1 };
    private static final byte[] CP = { (byte)0xd1,3,0,0,1 };
    private short complement(short i, boolean field) {
        byte[] c=field?CP:CN;
        return i<c.length ? (short)(c[i]&255) : 0;
    }
    private void fold(short high, boolean field) {
        Util.arrayFillNonAtomic(work,(short)64,(short)64,(byte)0);
        Util.arrayCopyNonAtomic(work,(short)0,work,(short)64,(short)32);
        short length=field?(short)5:(short)17;
        for(short i=0;i<high;i++) {
            short carry=0;
            for(short j=0;j<length;j++) {
                short at=(short)(64+i+j);
                short v=(short)((work[(short)(32+i)]&255)*complement(j,field)+(work[at]&255)+carry);
                work[at]=(byte)v; carry=(short)((v>>8)&255);
            }
            for(short j=(short)(i+length);j<64;j++) {
                short at=(short)(64+j);
                short v=(short)((work[at]&255)+carry);
                work[at]=(byte)v; carry=(short)((v>>8)&255);
            }
        }
        Util.arrayCopyNonAtomic(work,(short)64,work,(short)0,(short)64);
    }
    private void subtract(short offset) {
        short borrow=0;
        for(short i=95;i>=0;i--) {
            short v=(short)((squares[(short)(192+i)]&255)-(squares[(short)(offset+i)]&255)-borrow);
            squares[(short)(192+i)]=(byte)v; borrow=(short)((v>>15)&1);
        }
    }
    void clear() {
        Util.arrayFillNonAtomic(input,(short)0,(short)96,(byte)0);
        Util.arrayFillNonAtomic(squares,(short)0,(short)288,(byte)0);
        Util.arrayFillNonAtomic(work,(short)0,(short)128,(byte)0);
    }
}
