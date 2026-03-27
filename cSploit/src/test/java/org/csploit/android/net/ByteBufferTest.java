package org.csploit.android.net;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for ByteBuffer.
 * Covers append, indexOf (including off-by-one edge cases), replace, and query methods.
 */
public class ByteBufferTest {

    // ── initial state ─────────────────────────────────────────────────────────

    @Test
    public void newBuffer_isEmpty() {
        ByteBuffer buf = new ByteBuffer();
        assertTrue(buf.isEmpty());
        assertEquals(0, buf.getLength());
    }

    @Test
    public void newBuffer_getDataReturnsNull() {
        ByteBuffer buf = new ByteBuffer();
        assertNull(buf.getData());
    }

    // ── constructor with byte[] ───────────────────────────────────────────────

    @Test
    public void byteArrayConstructor_setsData() {
        byte[] data = {1, 2, 3};
        ByteBuffer buf = new ByteBuffer(data);
        assertFalse(buf.isEmpty());
        assertEquals(3, buf.getLength());
        assertArrayEquals(data, buf.getData());
    }

    @Test
    public void byteArrayConstructor_doesNotAliasInput() {
        byte[] data = {10, 20, 30};
        ByteBuffer buf = new ByteBuffer(data);
        data[0] = 99;
        assertEquals("Buffer must not reflect mutation of original array", 10, buf.getData()[0]);
    }

    // ── append ────────────────────────────────────────────────────────────────

    @Test
    public void append_toEmptyBuffer() {
        ByteBuffer buf = new ByteBuffer();
        byte[] chunk = {65, 66, 67}; // "ABC"
        buf.append(chunk, chunk.length);
        assertEquals(3, buf.getLength());
        assertArrayEquals(chunk, buf.getData());
    }

    @Test
    public void append_concatenatesBytes() {
        ByteBuffer buf = new ByteBuffer();
        buf.append(new byte[]{1, 2}, 2);
        buf.append(new byte[]{3, 4}, 2);
        assertArrayEquals(new byte[]{1, 2, 3, 4}, buf.getData());
    }

    @Test
    public void append_withLengthLessThanArray() {
        ByteBuffer buf = new ByteBuffer();
        byte[] chunk = {10, 20, 30, 40};
        buf.append(chunk, 2); // only first 2 bytes
        assertEquals(2, buf.getLength());
        assertArrayEquals(new byte[]{10, 20}, buf.getData());
    }

    // ── indexOf ───────────────────────────────────────────────────────────────

    @Test
    public void indexOf_emptyBuffer_returnsMinusOne() {
        ByteBuffer buf = new ByteBuffer();
        assertEquals(-1, buf.indexOf(new byte[]{1}));
    }

    @Test
    public void indexOf_patternFoundAtStart() {
        ByteBuffer buf = new ByteBuffer(new byte[]{10, 20, 30, 40});
        assertEquals(0, buf.indexOf(new byte[]{10, 20}));
    }

    @Test
    public void indexOf_patternFoundInMiddle() {
        ByteBuffer buf = new ByteBuffer(new byte[]{1, 2, 3, 4, 5});
        assertEquals(1, buf.indexOf(new byte[]{2, 3}));
    }

    /** Regression: off-by-one – pattern at the very end of the buffer must be found. */
    @Test
    public void indexOf_patternAtEnd_found() {
        ByteBuffer buf = new ByteBuffer(new byte[]{1, 2, 3, 4, 5});
        assertEquals(3, buf.indexOf(new byte[]{4, 5}));
    }

    /** Regression: single-byte buffer equal to single-byte pattern. */
    @Test
    public void indexOf_patternEqualsEntireBuffer() {
        ByteBuffer buf = new ByteBuffer(new byte[]{42});
        assertEquals(0, buf.indexOf(new byte[]{42}));
    }

    @Test
    public void indexOf_patternNotFound_returnsMinusOne() {
        ByteBuffer buf = new ByteBuffer(new byte[]{1, 2, 3});
        assertEquals(-1, buf.indexOf(new byte[]{9, 9}));
    }

    @Test
    public void indexOf_patternLongerThanBuffer_returnsMinusOne() {
        ByteBuffer buf = new ByteBuffer(new byte[]{1, 2});
        assertEquals(-1, buf.indexOf(new byte[]{1, 2, 3}));
    }

    @Test
    public void indexOf_withStartOffset_skipsEarlierMatch() {
        ByteBuffer buf = new ByteBuffer(new byte[]{5, 5, 5, 5});
        // First match is at 0, but we start at 1
        assertEquals(1, buf.indexOf(new byte[]{5}, 1));
    }

    @Test
    public void indexOf_nullPattern_returnsMinusOne() {
        ByteBuffer buf = new ByteBuffer(new byte[]{1, 2, 3});
        assertEquals(-1, buf.indexOf(null));
    }

    // ── replace ───────────────────────────────────────────────────────────────

    @Test
    public void replace_singleOccurrence() {
        ByteBuffer buf = new ByteBuffer("hello world".getBytes());
        buf.replace("world".getBytes(), "java".getBytes());
        assertEquals("hello java", buf.toString());
    }

    @Test
    public void replace_multipleOccurrences() {
        ByteBuffer buf = new ByteBuffer("aXaXa".getBytes());
        buf.replace("X".getBytes(), "Y".getBytes());
        assertEquals("aYaYa", buf.toString());
    }

    @Test
    public void replace_patternNotFound_noChange() {
        ByteBuffer buf = new ByteBuffer("abc".getBytes());
        buf.replace("z".getBytes(), "q".getBytes());
        assertEquals("abc", buf.toString());
    }

    // ── getLength / isEmpty ───────────────────────────────────────────────────

    @Test
    public void getLength_afterAppend_correctCount() {
        ByteBuffer buf = new ByteBuffer();
        buf.append(new byte[]{1, 2, 3}, 3);
        buf.append(new byte[]{4, 5}, 2);
        assertEquals(5, buf.getLength());
    }

    @Test
    public void getData_returnsCopy() {
        ByteBuffer buf = new ByteBuffer(new byte[]{7, 8, 9});
        byte[] d1 = buf.getData();
        byte[] d2 = buf.getData();
        assertNotSame("getData must return defensive copies", d1, d2);
        assertArrayEquals(d1, d2);
    }
}
