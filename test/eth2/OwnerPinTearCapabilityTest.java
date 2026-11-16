package com.nuri.eth2.test;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

/**
 * Simulator capability probe for the W29a PIN/PUK tear-safety analysis. Pure
 * simulator: never opens a reader.
 *
 * jcardsim 3.0.5.11 SimulatorRuntime.abortTransaction() only clears the
 * transaction depth flag and restores nothing, so the simulator CANNOT model
 * the hardware's transaction rollback. This class documents that limitation
 * programmatically:
 *
 *  - Probe A asserts that an OwnerPIN.update performed inside an aborted
 *    transaction still PERSISTS in this simulator. On real hardware the Java
 *    Card API guarantees the opposite (update's copy "must use the transaction
 *    facility" when a transaction is in progress), so Probe A pins the sim
 *    limitation, NOT hardware behaviour.
 *  - Probe B asserts that a wrong-PIN presentation inside an aborted
 *    transaction also persists (try counter stays decremented). This matches
 *    BOTH the simulator and the hardware spec (try-counter updates during PIN
 *    presentation "shall not participate in the transaction"), so Probe B is a
 *    spec-conformance check the simulator happens to model correctly.
 *
 * If a future jcardsim implements real rollback, Probe A fails: the harness
 * can then be upgraded to true rollback tests instead of this documented
 * limitation. Hardware tear atomicity of NuriEthSignerV2 remains UNVERIFIED
 * until tested on a physical card.
 */
public final class OwnerPinTearCapabilityTest {

    private static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
        System.out.println("ok   " + what);
    }

    public static void main(String[] args) {
        // JCSystem delegates to SimulatorSystem.instance(); a live CardSimulator
        // must exist on this thread first.
        new CardSimulator(new SimulatorRuntime());

        // Probe A: update inside an aborted transaction persists in jcardsim
        // (no heap restore) - documents the simulator's limitation.
        OwnerPIN p = new OwnerPIN((byte) 3, (byte) 16);
        p.update("1111".getBytes(), (short) 0, (byte) 4);
        check(p.getTriesRemaining() == 3, "probe A setup: fresh counter 3");
        JCSystem.beginTransaction();
        p.update("2222".getBytes(), (short) 0, (byte) 4);
        JCSystem.abortTransaction();
        check(p.check("2222".getBytes(), (short) 0, (byte) 4),
                "probe A: jcardsim abortTransaction does NOT roll back OwnerPIN.update (sim limitation; hardware WOULD roll back per spec)");
        check(p.getTriesRemaining() == 3, "probe A: successful check reset the counter");

        // Probe B: a wrong-PIN presentation inside an aborted transaction keeps
        // its try-counter decrement (spec-required non-transactional state).
        OwnerPIN q = new OwnerPIN((byte) 3, (byte) 16);
        q.update("1111".getBytes(), (short) 0, (byte) 4);
        JCSystem.beginTransaction();
        check(!q.check("9999".getBytes(), (short) 0, (byte) 4), "probe B: wrong PIN does not validate");
        JCSystem.abortTransaction();
        check(q.getTriesRemaining() == 2, "probe B: try counter stays decremented after abort (2 left)");
        check(q.check("1111".getBytes(), (short) 0, (byte) 4), "probe B: correct PIN still works after aborted transaction");

        System.out.println("OWNERPIN_TEAR_CAPABILITY_OK jcardsim models non-transactional try counters, "
                + "but NOT transaction rollback; hardware tear atomicity is UNVERIFIED here");
    }
}
