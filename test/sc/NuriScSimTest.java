// SPDX-License-Identifier: MIT
package test.sc;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.nuri.sc.NuriSecureChannelApplet;
import java.util.Arrays;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/** Deterministic jCardSim test of NuriSecureChannelApplet + stdin APDU helpers. */
public final class NuriScSimTest {
    public static final String AID = "4E55524953433031";
    private static int checks = 0;

    public static CardSimulator install() {
        CardSimulator sim = new CardSimulator();
        sim.installApplet(AIDUtil.create(AID), NuriSecureChannelApplet.class);
        ResponseAPDU sel = sim.transmitCommand(new CommandAPDU(AIDUtil.select(AID)));
        if (sel.getSW() != 0x9000) throw new AssertionError("SELECT failed: " + Integer.toHexString(sel.getSW()));
        return sim;
    }

    public static byte[] hex(String s) {
        String clean = s.replaceAll("\\s+", "");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static void eq(String label, int exp, int got) {
        if (exp != got) {
            throw new AssertionError(label + ": expected 0x" + Integer.toHexString(exp) + " got 0x" + Integer.toHexString(got));
        }
        checks++;
    }

    public static void main(String[] args) {
        CardSimulator sim = install();

        ResponseAPDU st = sim.transmitCommand(new CommandAPDU(0x80, 0x01, 0x00, 0x00, 5));
        eq("status sw", 0x9000, st.getSW());
        byte[] stData = st.getData();
        eq("status len", 5, stData.length);
        eq("status ver", 1, stData[0] & 0xFF);
        eq("status open=0", 0, stData[2] & 0xFF);
        eq("status pinSet=0", 0, stData[3] & 0xFF);
        eq("status tries=5", 5, stData[4] & 0xFF);

        ResponseAPDU pk = sim.transmitCommand(new CommandAPDU(0x80, 0x02, 0x00, 0x00, 65));
        eq("pubkey sw", 0x9000, pk.getSW());
        eq("pubkey len", 65, pk.getData().length);
        eq("pubkey 0x04", 0x04, pk.getData()[0] & 0xFF);

        for (int ins : new int[] {0x20, 0x21, 0x30, 0x40, 0x50}) {
            ResponseAPDU r = sim.transmitCommand(new CommandAPDU(0x80, ins, 0x00, 0x00, new byte[] {1, 2, 3, 4}));
            eq("plaintext rejected ins=" + ins, 0x6985, r.getSW());
        }

        ResponseAPDU w0 = sim.transmitCommand(new CommandAPDU(0x80, 0x11, 0x01, 0x00, new byte[48]));
        eq("wrap before open", 0x6985, w0.getSW());

        ResponseAPDU badOpen = sim.transmitCommand(new CommandAPDU(0x80, 0x10, 0x01, 0x00, new byte[65]));
        eq("open bad point prefix", 0x6A80, badOpen.getSW());

        byte[] gPoint = hex(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        );
        ResponseAPDU op = sim.transmitCommand(new CommandAPDU(0x80, 0x10, 0x01, 0x00, gPoint, 256));
        eq("open sw", 0x9000, op.getSW());
        byte[] opData = op.getData();
        if (opData.length < 82) throw new AssertionError("short OPEN data: " + opData.length);
        eq("card_eph 0x04", 0x04, opData[0] & 0xFF);
        int sigLen = opData[73] & 0xFF;
        eq("open total len", 74 + sigLen, opData.length);
        if (Arrays.equals(gPoint, Arrays.copyOf(opData, 65))) {
            throw new AssertionError("card_eph collided with G");
        }

        ResponseAPDU stOpen = sim.transmitCommand(new CommandAPDU(0x80, 0x01, 0x00, 0x00, 5));
        eq("status open=1", 1, stOpen.getData()[2] & 0xFF);

        ResponseAPDU badWrap = sim.transmitCommand(new CommandAPDU(0x80, 0x11, 0x01, 0x00, new byte[48]));
        eq("bad wrap sw", 0x6988, badWrap.getSW());
        ResponseAPDU stWiped = sim.transmitCommand(new CommandAPDU(0x80, 0x01, 0x00, 0x00, 5));
        eq("status wiped open=0", 0, stWiped.getData()[2] & 0xFF);

        System.out.println("NURI_SC_SIM_JAVA_OK checks=" + checks);
    }
}
