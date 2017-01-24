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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Input stream supporting single-byte peek operations.
 */
class PeekInputStream extends InputStream {

    /** underlying stream */
    private final InputStream in;
    /** peeked byte */
    private int peekb = -1;

    /**
     * Creates new PeekInputStream on top of given underlying stream.
     */
    PeekInputStream(InputStream in) {
        this.in = in;
    }

    /**
     * Peeks at next byte value in stream.  Similar to read(), except
     * that it does not consume the read value.
     */
    int peek() throws IOException {
        return (peekb >= 0) ? peekb : (peekb = in.read());
    }

    public int read() throws IOException {
        if (peekb >= 0) {
            int v = peekb;
            peekb = -1;
            return v;
        } else {
            return in.read();
        }
    }

    public int read(byte[] b, int off, int len) throws IOException {
        if (len == 0) {
            return 0;
        } else if (peekb < 0) {
            return in.read(b, off, len);
        } else {
            b[off++] = (byte) peekb;
            len--;
            peekb = -1;
            int n = in.read(b, off, len);
            return (n >= 0) ? (n + 1) : 1;
        }
    }

    void readFully(byte[] b, int off, int len) throws IOException {
        int n = 0;
        while (n < len) {
            int count = read(b, off + n, len - n);
            if (count < 0) {
                throw new EOFException();
            }
            n += count;
        }
    }

    public long skip(long n) throws IOException {
        if (n <= 0) {
            return 0;
        }
        int skipped = 0;
        if (peekb >= 0) {
            peekb = -1;
            skipped++;
            n--;
        }
        return skipped + skip(n);
    }

    public int available() throws IOException {
        return in.available() + ((peekb >= 0) ? 1 : 0);
    }

    public void close() throws IOException {
        in.close();
    }
}
