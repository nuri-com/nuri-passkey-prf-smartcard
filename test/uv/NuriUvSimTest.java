package com.nuri.uv;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public final class NuriUvSimTest {
    private static final String UV = "4E5552494155544801";
    private static final String CLIENT = "4E5552494155544802";
    private static int checks;

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte)Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    private static byte[] tx(CardSimulator sim, String apdu, int expected) {
        ResponseAPDU response = sim.transmitCommand(new CommandAPDU(hex(apdu)));
        check(response.getSW() == expected, String.format("SW %04X != %04X for %s", response.getSW(), expected, apdu));
        return response.getData();
    }

    private static void select(CardSimulator sim, String aid) {
        tx(sim, "00A40400" + String.format("%02X", aid.length() / 2) + aid, 0x9000);
    }

    private static void client(CardSimulator sim, int expected) {
        select(sim, CLIENT);
        byte[] data = tx(sim, "0001000000", expected);
        if (expected == 0x9000) check(data.length == 2 && data[0] == 0x4F && data[1] == 0x4B, "client response");
    }

    private static void pin(CardSimulator sim) {
        select(sim, UV);
        tx(sim, "002000000431323334", 0x9000);
    }

    private static void finger(CardSimulator sim, int expected) {
        select(sim, UV);
        tx(sim, "002A000000", expected);
    }

    public static void main(String[] args) {
        MatcherFactory.bitmap = 3;
        MatcherFactory.matchResult = BiometricMatcher.MATCH_OK;
        MatcherFactory.enrollResult = 0;
        CardSimulator sim = new CardSimulator();
        sim.installApplet(AIDUtil.create(UV), NuriUvApplet.class);
        sim.installApplet(AIDUtil.create(CLIENT), NuriUvTestClient.class);

        select(sim, UV);
        byte[] status = tx(sim, "0007000000", 0x9000);
        check(status.length == 2 && status[0] == 0 && status[1] == 0, "initial PIN-only status");
        client(sim, 0x6982);

        select(sim, UV);
        tx(sim, "003100000431323334", 0x9000);
        tx(sim, "002000000430303030", 0x63C4);
        pin(sim);
        client(sim, 0x9000);

        select(sim, UV);
        tx(sim, "0038010000", 0x9000); // Initial PIN authorized registered templates; OR logs out.
        client(sim, 0x6982);
        finger(sim, 0x9000);
        client(sim, 0x9000);

        select(sim, UV);
        tx(sim, "0035000000", 0x9000);
        client(sim, 0x6982);
        pin(sim);
        select(sim, UV);
        tx(sim, "0038020000", 0x9000); // AND; logs out.
        client(sim, 0x6982);
        pin(sim);
        client(sim, 0x6982); // PIN alone insufficient under AND.
        finger(sim, 0x9000);
        client(sim, 0x9000);

        select(sim, UV);
        tx(sim, "0035000000", 0x9000);
        finger(sim, 0x9000);
        client(sim, 0x6982); // Finger alone insufficient under AND.
        pin(sim);
        client(sim, 0x9000);

        select(sim, UV);
        tx(sim, "0035000000", 0x9000);
        tx(sim, "0038000000", 0x6982); // Cannot downgrade policy while logged out.
        pin(sim);
        finger(sim, 0x9000);
        select(sim, UV);
        tx(sim, "0038010000", 0x9000); // AND requires both before changing to OR.
        MatcherFactory.matchResult = BiometricMatcher.MATCH_FAILED;
        finger(sim, 0x63C2);
        client(sim, 0x6982);
        finger(sim, 0x63C1);
        finger(sim, 0x6983);
        pin(sim); // PIN remains the OR fallback and resets finger retries.
        client(sim, 0x9000);

        select(sim, UV);
        tx(sim, "0035000000", 0x9000);
        MatcherFactory.matchResult = BiometricMatcher.MATCH_TIMEOUT;
        finger(sim, 0x63E9);
        MatcherFactory.matchResult = BiometricMatcher.MATCH_FAILED;
        finger(sim, 0x63C2); // Timeout left all three retries available.
        finger(sim, 0x63C1);
        finger(sim, 0x6983);
        pin(sim);

        System.out.println("NURI_UV_SIM_TEST_OK (" + checks + " checks passed)");
    }
}
