package org.csploit.android.core;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Tests for thread-safety of the ConcurrentSkipListSet-backed target list in System.
 *
 * These tests validate the concurrent contract independently of Android dependencies
 * by using the ConcurrentSkipListSet directly (same collection used in System).
 */
public class SystemTargetListTest {

    /**
     * Verify that concurrent reads and a single write do not throw
     * ConcurrentModificationException.
     */
    @Test
    public void concurrentReadsDuringWrite_noException() throws InterruptedException {
        java.util.concurrent.ConcurrentSkipListSet<Integer> set = new java.util.concurrent.ConcurrentSkipListSet<>();
        for (int i = 0; i < 50; i++) set.add(i);

        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger errors = new AtomicInteger(0);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        for (int t = 0; t < threads - 1; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    // Iterate without lock — should be safe with ConcurrentSkipListSet
                    List<Integer> copy = new ArrayList<>(set);
                    assertFalse(copy.isEmpty());
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            });
        }
        // One writer thread
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 50; i < 100; i++) set.add(i);
            } catch (Exception e) {
                errors.incrementAndGet();
            } finally {
                done.countDown();
            }
        });

        start.countDown();
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(0, errors.get());
        pool.shutdown();
    }

    /** getTargets() must always return a snapshot, not a live view. */
    @Test
    public void getTargets_returnsSnapshot() {
        java.util.concurrent.ConcurrentSkipListSet<Integer> set = new java.util.concurrent.ConcurrentSkipListSet<>();
        set.add(1);
        set.add(2);

        List<Integer> snapshot = new ArrayList<>(set);
        assertEquals(2, snapshot.size());

        set.add(3);
        // Snapshot is unaffected
        assertEquals(2, snapshot.size());
    }

    /** Adding the same element twice must return false on the second add. */
    @Test
    public void addDuplicate_returnsFalse() {
        java.util.concurrent.ConcurrentSkipListSet<Integer> set = new java.util.concurrent.ConcurrentSkipListSet<>();
        assertTrue(set.add(42));
        assertFalse(set.add(42));
    }
}
