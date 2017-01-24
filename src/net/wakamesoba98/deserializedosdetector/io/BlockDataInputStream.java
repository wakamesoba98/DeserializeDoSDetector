/*
 * Copyright (c) 1996, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package net.wakamesoba98.deserializedosdetector.io;
import java.io.*;

/**
 * Input stream with two modes: in default mode, inputs data written in the
 * same format as DataOutputStream; in "block data" mode, inputs data
 * bracketed by block data markers (see object serialization specification
 * for details).  Buffering depends on block data mode: when in default
 * mode, no data is buffered in advance; when in block data mode, all data
 * for the current data block is read in at once (and buffered).
 */
class BlockDataInputStream
        extends InputStream implements DataInput, ObjectStreamConstants
{
    /** maximum data block length */
    private static final int MAX_BLOCK_SIZE = 1024;
    /** maximum data block header length */
    private static final int MAX_HEADER_SIZE = 5;
    /** (tunable) length of char buffer (for reading strings) */
    private static final int CHAR_BUF_SIZE = 256;
    /** readBlockHeader() return value indicating header read may block */
    private static final int HEADER_BLOCKED = -2;

    /** buffer for reading general/block data */
    private final byte[] buf = new byte[MAX_BLOCK_SIZE];
    /** buffer for reading block data headers */
    private final byte[] hbuf = new byte[MAX_HEADER_SIZE];
    /** char buffer for fast string reads */
    private final char[] cbuf = new char[CHAR_BUF_SIZE];

    /** block data mode */
    private boolean blkmode = false;

    // block data state fields; values meaningful only when blkmode true
    /** current offset into buf */
    private int pos = 0;
    /** end offset of valid data in buf, or -1 if no more block data */
    private int end = -1;
    /** number of bytes in current block yet to be read from stream */
    private int unread = 0;

    /** underlying stream (wrapped in peekable filter stream) */
    private final PeekInputStream in;
    /** loopback stream (for data reads that span data blocks) */
    private final DataInputStream din;

    /**
     * Creates new BlockDataInputStream on top of given underlying stream.
     * Block data mode is turned off by default.
     */
    BlockDataInputStream(InputStream in) {
        this.in = new PeekInputStream(in);
        din = new DataInputStream(this);
    }

    /**
     * Sets block data mode to the given mode (true == on, false == off)
     * and returns the previous mode value.  If the new mode is the same as
     * the old mode, no action is taken.  Throws IllegalStateException if
     * block data mode is being switched from on to off while unconsumed
     * block data is still present in the stream.
     */
    boolean setBlockDataMode(boolean newmode) throws IOException {
        if (blkmode == newmode) {
            return blkmode;
        }
        if (newmode) {
            pos = 0;
            end = 0;
            unread = 0;
        } else if (pos < end) {
            throw new IllegalStateException("unread block data");
        }
        blkmode = newmode;
        return !blkmode;
    }

    /**
     * Returns true if the stream is currently in block data mode, false
     * otherwise.
     */
    boolean getBlockDataMode() {
        return blkmode;
    }

    /**
     * If in block data mode, skips to the end of the current group of data
     * blocks (but does not unset block data mode).  If not in block data
     * mode, throws an IllegalStateException.
     */
    void skipBlockData() throws IOException {
        if (!blkmode) {
            throw new IllegalStateException("not in block data mode");
        }
        while (end >= 0) {
            refill();
        }
    }

    /**
     * Attempts to read in the next block data header (if any).  If
     * canBlock is false and a full header cannot be read without possibly
     * blocking, returns HEADER_BLOCKED, else if the next element in the
     * stream is a block data header, returns the block data length
     * specified by the header, else returns -1.
     */
    int readBlockHeader(boolean canBlock) throws IOException {
        try {
            for (;;) {
                int avail = canBlock ? Integer.MAX_VALUE : in.available();
                if (avail == 0) {
                    return HEADER_BLOCKED;
                }

                int tc = in.peek();
                switch (tc) {
                    case TC_BLOCKDATA:
                        if (avail < 2) {
                            return HEADER_BLOCKED;
                        }
                        in.readFully(hbuf, 0, 2);
                        return hbuf[1] & 0xFF;

                    case TC_BLOCKDATALONG:
                        if (avail < 5) {
                            return HEADER_BLOCKED;
                        }
                        in.readFully(hbuf, 0, 5);
                        int len = Bits.getInt(hbuf, 1);
                        if (len < 0) {
                            throw new StreamCorruptedException(
                                    "illegal block data header length: " +
                                            len);
                        }
                        return len;

                    /*
                     * TC_RESETs may occur in between data blocks.
                     * Unfortunately, this case must be parsed at a lower
                     * level than other typecodes, since primitive data
                     * reads may span data blocks separated by a TC_RESET.
                     */
                    case TC_RESET:
                        in.read();
                        // handleReset();
                        break;

                    default:
                        if (tc >= 0 && (tc < TC_BASE || tc > TC_MAX)) {
                            throw new StreamCorruptedException(
                                    String.format("invalid type code: %02X",
                                            tc));
                        }
                        return -1;
                }
            }
        } catch (EOFException ex) {
            throw new StreamCorruptedException(
                    "unexpected EOF while reading block data header");
        }
    }

    /**
     * Refills internal buffer buf with block data.  Any data in buf at the
     * time of the call is considered consumed.  Sets the pos, end, and
     * unread fields to reflect the new amount of available block data; if
     * the next element in the stream is not a data block, sets pos and
     * unread to 0 and end to -1.
     */
    private void refill() throws IOException {
        try {
            do {
                pos = 0;
                if (unread > 0) {
                    int n =
                            in.read(buf, 0, Math.min(unread, MAX_BLOCK_SIZE));
                    if (n >= 0) {
                        end = n;
                        unread -= n;
                    } else {
                        throw new StreamCorruptedException(
                                "unexpected EOF in middle of data block");
                    }
                } else {
                    int n = readBlockHeader(true);
                    if (n >= 0) {
                        end = 0;
                        unread = n;
                    } else {
                        end = -1;
                        unread = 0;
                    }
                }
            } while (pos == end);
        } catch (IOException ex) {
            pos = 0;
            end = -1;
            unread = 0;
            throw ex;
        }
    }

    /**
     * If in block data mode, returns the number of unconsumed bytes
     * remaining in the current data block.  If not in block data mode,
     * throws an IllegalStateException.
     */
    int currentBlockRemaining() {
        if (blkmode) {
            return (end >= 0) ? (end - pos) + unread : 0;
        } else {
            throw new IllegalStateException();
        }
    }

    /**
     * Peeks at (but does not consume) and returns the next byte value in
     * the stream, or -1 if the end of the stream/block data (if in block
     * data mode) has been reached.
     */
    int peek() throws IOException {
        if (blkmode) {
            if (pos == end) {
                refill();
            }
            return (end >= 0) ? (buf[pos] & 0xFF) : -1;
        } else {
            return in.peek();
        }
    }

    /**
     * Peeks at (but does not consume) and returns the next byte value in
     * the stream, or throws EOFException if end of stream/block data has
     * been reached.
     */
    byte peekByte() throws IOException {
        int val = peek();
        if (val < 0) {
            throw new EOFException();
        }
        return (byte) val;
    }


    /* ----------------- generic input stream methods ------------------ */
    /*
     * The following methods are equivalent to their counterparts in
     * InputStream, except that they interpret data block boundaries and
     * read the requested data from within data blocks when in block data
     * mode.
     */

    public int read() throws IOException {
        if (blkmode) {
            if (pos == end) {
                refill();
            }
            return (end >= 0) ? (buf[pos++] & 0xFF) : -1;
        } else {
            return in.read();
        }
    }

    public int read(byte[] b, int off, int len) throws IOException {
        return read(b, off, len, false);
    }

    public long skip(long len) throws IOException {
        long remain = len;
        while (remain > 0) {
            if (blkmode) {
                if (pos == end) {
                    refill();
                }
                if (end < 0) {
                    break;
                }
                int nread = (int) Math.min(remain, end - pos);
                remain -= nread;
                pos += nread;
            } else {
                int nread = (int) Math.min(remain, MAX_BLOCK_SIZE);
                if ((nread = in.read(buf, 0, nread)) < 0) {
                    break;
                }
                remain -= nread;
            }
        }
        return len - remain;
    }

    public int available() throws IOException {
        if (blkmode) {
            if ((pos == end) && (unread == 0)) {
                int n;
                while ((n = readBlockHeader(false)) == 0) ;
                switch (n) {
                    case HEADER_BLOCKED:
                        break;

                    case -1:
                        pos = 0;
                        end = -1;
                        break;

                    default:
                        pos = 0;
                        end = 0;
                        unread = n;
                        break;
                }
            }
            // avoid unnecessary call to in.available() if possible
            int unreadAvail = (unread > 0) ?
                    Math.min(in.available(), unread) : 0;
            return (end >= 0) ? (end - pos) + unreadAvail : 0;
        } else {
            return in.available();
        }
    }

    public void close() throws IOException {
        if (blkmode) {
            pos = 0;
            end = -1;
            unread = 0;
        }
        in.close();
    }

    /**
     * Attempts to read len bytes into byte array b at offset off.  Returns
     * the number of bytes read, or -1 if the end of stream/block data has
     * been reached.  If copy is true, reads values into an intermediate
     * buffer before copying them to b (to avoid exposing a reference to
     * b).
     */
    int read(byte[] b, int off, int len, boolean copy) throws IOException {
        if (len == 0) {
            return 0;
        } else if (blkmode) {
            if (pos == end) {
                refill();
            }
            if (end < 0) {
                return -1;
            }
            int nread = Math.min(len, end - pos);
            System.arraycopy(buf, pos, b, off, nread);
            pos += nread;
            return nread;
        } else if (copy) {
            int nread = in.read(buf, 0, Math.min(len, MAX_BLOCK_SIZE));
            if (nread > 0) {
                System.arraycopy(buf, 0, b, off, nread);
            }
            return nread;
        } else {
            return in.read(b, off, len);
        }
    }

    /* ----------------- primitive data input methods ------------------ */
    /*
     * The following methods are equivalent to their counterparts in
     * DataInputStream, except that they interpret data block boundaries
     * and read the requested data from within data blocks when in block
     * data mode.
     */

    public void readFully(byte[] b) throws IOException {
        readFully(b, 0, b.length, false);
    }

    public void readFully(byte[] b, int off, int len) throws IOException {
        readFully(b, off, len, false);
    }

    public void readFully(byte[] b, int off, int len, boolean copy)
            throws IOException
    {
        while (len > 0) {
            int n = read(b, off, len, copy);
            if (n < 0) {
                throw new EOFException();
            }
            off += n;
            len -= n;
        }
    }

    public int skipBytes(int n) throws IOException {
        return din.skipBytes(n);
    }

    public boolean readBoolean() throws IOException {
        int v = read();
        if (v < 0) {
            throw new EOFException();
        }
        return (v != 0);
    }

    public byte readByte() throws IOException {
        int v = read();
        if (v < 0) {
            throw new EOFException();
        }
        return (byte) v;
    }

    public int readUnsignedByte() throws IOException {
        int v = read();
        if (v < 0) {
            throw new EOFException();
        }
        return v;
    }

    public char readChar() throws IOException {
        if (!blkmode) {
            pos = 0;
            in.readFully(buf, 0, 2);
        } else if (end - pos < 2) {
            return din.readChar();
        }
        char v = Bits.getChar(buf, pos);
        pos += 2;
        return v;
    }

    public short readShort() throws IOException {
        if (!blkmode) {
            pos = 0;
            in.readFully(buf, 0, 2);
        } else if (end - pos < 2) {
            return din.readShort();
        }
        short v = Bits.getShort(buf, pos);
        pos += 2;
        return v;
    }

    public int readUnsignedShort() throws IOException {
        if (!blkmode) {
            pos = 0;
            in.readFully(buf, 0, 2);
        } else if (end - pos < 2) {
            return din.readUnsignedShort();
        }
        int v = Bits.getShort(buf, pos) & 0xFFFF;
        pos += 2;
        return v;
    }

    public int readInt() throws IOException {
        if (!blkmode) {
            pos = 0;
            in.readFully(buf, 0, 4);
        } else if (end - pos < 4) {
            return din.readInt();
        }
        int v = Bits.getInt(buf, pos);
        pos += 4;
        return v;
    }

    public float readFloat() throws IOException {
        if (!blkmode) {
            pos = 0;
            in.readFully(buf, 0, 4);
        } else if (end - pos < 4) {
            return din.readFloat();
        }
        float v = Bits.getFloat(buf, pos);
        pos += 4;
        return v;
    }

    public long readLong() throws IOException {
        if (!blkmode) {
            pos = 0;
            in.readFully(buf, 0, 8);
        } else if (end - pos < 8) {
            return din.readLong();
        }
        long v = Bits.getLong(buf, pos);
        pos += 8;
        return v;
    }

    public double readDouble() throws IOException {
        if (!blkmode) {
            pos = 0;
            in.readFully(buf, 0, 8);
        } else if (end - pos < 8) {
            return din.readDouble();
        }
        double v = Bits.getDouble(buf, pos);
        pos += 8;
        return v;
    }

    public String readUTF() throws IOException {
        return readUTFBody(readUnsignedShort());
    }

    @SuppressWarnings("deprecation")
    public String readLine() throws IOException {
        return din.readLine();      // deprecated, not worth optimizing
    }

    /**
     * Reads in the "body" (i.e., the UTF representation minus the 2-byte
     * or 8-byte length header) of a UTF encoding, which occupies the next
     * utflen bytes.
     */
    private String readUTFBody(long utflen) throws IOException {
        StringBuilder sbuf = new StringBuilder();
        if (!blkmode) {
            end = pos = 0;
        }

        while (utflen > 0) {
            int avail = end - pos;
            if (avail >= 3 || (long) avail == utflen) {
                utflen -= readUTFSpan(sbuf, utflen);
            } else {
                if (blkmode) {
                    // near block boundary, read one byte at a time
                    utflen -= readUTFChar(sbuf, utflen);
                } else {
                    // shift and refill buffer manually
                    if (avail > 0) {
                        System.arraycopy(buf, pos, buf, 0, avail);
                    }
                    pos = 0;
                    end = (int) Math.min(MAX_BLOCK_SIZE, utflen);
                    in.readFully(buf, avail, end - avail);
                }
            }
        }

        return sbuf.toString();
    }

    /**
     * Reads span of UTF-encoded characters out of internal buffer
     * (starting at offset pos and ending at or before offset end),
     * consuming no more than utflen bytes.  Appends read characters to
     * sbuf.  Returns the number of bytes consumed.
     */
    private long readUTFSpan(StringBuilder sbuf, long utflen)
            throws IOException
    {
        int cpos = 0;
        int start = pos;
        int avail = Math.min(end - pos, CHAR_BUF_SIZE);
        // stop short of last char unless all of utf bytes in buffer
        int stop = pos + ((utflen > avail) ? avail - 2 : (int) utflen);
        boolean outOfBounds = false;

        try {
            while (pos < stop) {
                int b1, b2, b3;
                b1 = buf[pos++] & 0xFF;
                switch (b1 >> 4) {
                    case 0:
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                    case 7:   // 1 byte format: 0xxxxxxx
                        cbuf[cpos++] = (char) b1;
                        break;

                    case 12:
                    case 13:  // 2 byte format: 110xxxxx 10xxxxxx
                        b2 = buf[pos++];
                        if ((b2 & 0xC0) != 0x80) {
                            throw new UTFDataFormatException();
                        }
                        cbuf[cpos++] = (char) (((b1 & 0x1F) << 6) |
                                ((b2 & 0x3F) << 0));
                        break;

                    case 14:  // 3 byte format: 1110xxxx 10xxxxxx 10xxxxxx
                        b3 = buf[pos + 1];
                        b2 = buf[pos + 0];
                        pos += 2;
                        if ((b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) {
                            throw new UTFDataFormatException();
                        }
                        cbuf[cpos++] = (char) (((b1 & 0x0F) << 12) |
                                ((b2 & 0x3F) << 6) |
                                ((b3 & 0x3F) << 0));
                        break;

                    default:  // 10xx xxxx, 1111 xxxx
                        throw new UTFDataFormatException();
                }
            }
        } catch (ArrayIndexOutOfBoundsException ex) {
            outOfBounds = true;
        } finally {
            if (outOfBounds || (pos - start) > utflen) {
                /*
                 * Fix for 4450867: if a malformed utf char causes the
                 * conversion loop to scan past the expected end of the utf
                 * string, only consume the expected number of utf bytes.
                 */
                pos = start + (int) utflen;
                throw new UTFDataFormatException();
            }
        }

        sbuf.append(cbuf, 0, cpos);
        return pos - start;
    }

    /**
     * Reads in single UTF-encoded character one byte at a time, appends
     * the character to sbuf, and returns the number of bytes consumed.
     * This method is used when reading in UTF strings written in block
     * data mode to handle UTF-encoded characters which (potentially)
     * straddle block-data boundaries.
     */
    private int readUTFChar(StringBuilder sbuf, long utflen)
            throws IOException
    {
        int b1, b2, b3;
        b1 = readByte() & 0xFF;
        switch (b1 >> 4) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:     // 1 byte format: 0xxxxxxx
                sbuf.append((char) b1);
                return 1;

            case 12:
            case 13:    // 2 byte format: 110xxxxx 10xxxxxx
                if (utflen < 2) {
                    throw new UTFDataFormatException();
                }
                b2 = readByte();
                if ((b2 & 0xC0) != 0x80) {
                    throw new UTFDataFormatException();
                }
                sbuf.append((char) (((b1 & 0x1F) << 6) |
                        ((b2 & 0x3F) << 0)));
                return 2;

            case 14:    // 3 byte format: 1110xxxx 10xxxxxx 10xxxxxx
                if (utflen < 3) {
                    if (utflen == 2) {
                        readByte();         // consume remaining byte
                    }
                    throw new UTFDataFormatException();
                }
                b2 = readByte();
                b3 = readByte();
                if ((b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) {
                    throw new UTFDataFormatException();
                }
                sbuf.append((char) (((b1 & 0x0F) << 12) |
                        ((b2 & 0x3F) << 6) |
                        ((b3 & 0x3F) << 0)));
                return 3;

            default:   // 10xx xxxx, 1111 xxxx
                throw new UTFDataFormatException();
        }
    }
}