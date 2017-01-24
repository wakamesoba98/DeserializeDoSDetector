/*
 * Copyright (c) 2017, wakamesoba98.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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
 */

package net.wakamesoba98.deserializedosdetector.io;

import net.wakamesoba98.deserializedosdetector.util.ColorPrint;

import java.io.*;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;

public class DeserializeDoSDetector implements ObjectStreamConstants {

    private static final int ARRAY_SIZE_MAX = 65536;
    private static final int REFERENCE_MAX = 32768;

    private BlockDataInputStream bin;
    private long totalArraySize = 0;
    private List<String> objectList;
    private List<List<Integer>> referencesList;
    private int nowObjectNumber = -1;
    private Deque<Integer> parentObjectNumberStack;
    private int referenceDepth = 0;
    private int referenceCount = 0;

    public DeserializeDoSDetector(InputStream in) {
        this.bin = new BlockDataInputStream(in);
        this.objectList = new ArrayList<>();
        this.referencesList = new ArrayList<>();
        this.parentObjectNumberStack = new LinkedList<>();
    }

    public void check() throws IOException {
        try {
            checkMagic();
            checkHeader();
        } catch (EOFException e) {
            ColorPrint.println("* Serialized stream ended unexpectedly.", ColorPrint.RED);
        }
        checkReferenceDepth();
    }

    private void checkMagic() throws IOException {
        short magic = bin.readShort();
        short version = bin.readShort();
        if (magic != STREAM_MAGIC || version != STREAM_VERSION) {
            throw new StreamCorruptedException(String.format("invalid stream header: %04X%04X", magic, version));
        }

        ColorPrint.println("* Magic number is correct.", ColorPrint.CYAN);
    }

    private void checkHeader() throws IOException {
        while (bin.available() > 0) {
            byte b = bin.peekByte();
            switch (b) {
                case TC_NULL:
                    readNull();
                    break;

                case TC_ARRAY:
                    checkArray();
                    break;

                case TC_CLASSDESC:
                case TC_PROXYCLASSDESC:
                    readClassDesc();
                    break;

                case TC_STRING:
                case TC_LONGSTRING:
                    nowObjectNumber++;
                    readString();
                    break;

                case TC_OBJECT:
                    nowObjectNumber++;
                    checkObject();
                    break;

                case TC_REFERENCE:
                    checkReference();
                    break;

                case TC_BLOCKDATA:
                case TC_BLOCKDATALONG:
                    bin.setBlockDataMode(false);
                    skipBlockDataHeader();
                    stackReference();
                    break;

                case TC_ENDBLOCKDATA:
                    bin.read();
                    parentObjectNumberStack.removeFirst();
                    break;

                default:
                    bin.read();
                    break;
            }
        }
    }

    private void checkArray() throws IOException {
        if (bin.readByte() != TC_ARRAY) {
            throw new InternalError();
        }

        readClassDesc();

        int arraySize = bin.readInt();
        if (arraySize > 0) {
            addTotalArraySize(arraySize);
        }
    }

    private String checkReference() throws IOException {
        if (bin.readByte() != TC_REFERENCE) {
            throw new InternalError();
        }

        int passHandle = bin.readInt() - baseWireHandle;
        if (passHandle < 0 || passHandle >= objectList.size()) {
            throw new StreamCorruptedException(
                    String.format("invalid handle value: %08X", passHandle +
                            baseWireHandle));
        }

        String objectName = objectList.get(passHandle);

        if (nowObjectNumber >= objectList.size()) {
            while (nowObjectNumber >= objectList.size()) {
                objectList.add(null);
            }
        }
        String item = objectList.get(nowObjectNumber);
        if (item == null) {
            objectList.set(nowObjectNumber, objectName);
        }

        addReferenceToObject(passHandle, nowObjectNumber);

        return objectName;
    }

    private void checkObject() throws IOException {
        if (bin.readByte() != TC_OBJECT) {
            throw new InternalError();
        }

        readClassDesc();

        Integer parent = parentObjectNumberStack.peekFirst();
        if (parent != null) {
            addReferenceToObject(nowObjectNumber, parent);
        }
    }

    private void addTotalArraySize(int size) throws UnsafeStreamException {
        totalArraySize += size;
        System.out.println(Long.toHexString(totalArraySize));
        if (totalArraySize > ARRAY_SIZE_MAX) {
            ColorPrint.println("* Array size too large. (it may be a deserialization DoS attack)", ColorPrint.RED);

            throw new UnsafeStreamException("Array size too large (it may be a deserialization DoS attack)");
        }
    }

    private void skipBlockDataHeader() throws IOException {
        int size = bin.readBlockHeader(false);
        for (int i = 0; i < size; i++) {
            bin.read();
        }
    }

    private ObjectStreamClass readClassDesc() throws IOException {
        byte tc = bin.peekByte();
        switch (tc) {
            case TC_NULL:
                readNull();
                break;
            case TC_REFERENCE:
                checkReference();
                break;
            case TC_PROXYCLASSDESC:
                nowObjectNumber++;
                checkProxyDesc();
                break;
            case TC_CLASSDESC:
                nowObjectNumber++;
                readNonProxyDesc();
                break;
            default:
                throw new StreamCorruptedException(
                        String.format("invalid type code: %02X", tc));
        }
        return null;
    }

    private void checkProxyDesc() throws IOException {
        if (bin.readByte() != TC_PROXYCLASSDESC) {
            throw new InternalError();
        }

        int numIfaces = bin.readInt();
        addTotalArraySize(numIfaces);

        for (int i = 0; i < numIfaces; i++) {
            bin.readUTF();
        }

        String name = bin.readUTF();
        Long suid = bin.readLong();
        boolean isProxy = false;

        byte flags = bin.readByte();
        boolean hasWriteObjectData = ((flags & ObjectStreamConstants.SC_WRITE_METHOD) != 0);
        boolean hasBlockExternalData = ((flags & ObjectStreamConstants.SC_BLOCK_DATA) != 0);
        boolean externalizable = ((flags & ObjectStreamConstants.SC_EXTERNALIZABLE) != 0);
        boolean sflag = ((flags & ObjectStreamConstants.SC_SERIALIZABLE) != 0);
        if (externalizable && sflag) {
            throw new InvalidClassException(
                    name, "serializable and externalizable flags conflict");
        }
        boolean serializable = externalizable || sflag;
        boolean isEnum = ((flags & ObjectStreamConstants.SC_ENUM) != 0);
        if (isEnum && suid != 0L) {
            throw new InvalidClassException(name,
                    "enum descriptor has non-zero serialVersionUID: " + suid);
        }

        int numFields = bin.readShort();
        if (isEnum && numFields != 0) {
            throw new InvalidClassException(name,
                    "enum descriptor has non-zero field count: " + numFields);
        }
        for (int i = 0; i < numFields; i++) {
            char tcode = (char) bin.readByte();
            String fname = bin.readUTF();
            String signature = ((tcode == 'L') || (tcode == '[')) ? readTypeString() : new String(new char[] { tcode });
        }
        skipCustomData();
        readClassDesc();

        objectList.add(name);

        ColorPrint.println("* " + name + " / " + suid + " / " + numFields, ColorPrint.MAGENTA);
    }

    private void readNonProxyDesc() throws IOException {
        if (bin.readByte() != TC_CLASSDESC) {
            throw new InternalError();
        }

        String name = bin.readUTF();
        Long suid = bin.readLong();
        boolean isProxy = false;

        byte flags = bin.readByte();
        boolean hasWriteObjectData = ((flags & ObjectStreamConstants.SC_WRITE_METHOD) != 0);
        boolean hasBlockExternalData = ((flags & ObjectStreamConstants.SC_BLOCK_DATA) != 0);
        boolean externalizable = ((flags & ObjectStreamConstants.SC_EXTERNALIZABLE) != 0);
        boolean sflag = ((flags & ObjectStreamConstants.SC_SERIALIZABLE) != 0);
        if (externalizable && sflag) {
            throw new InvalidClassException(
                    name, "serializable and externalizable flags conflict");
        }
        boolean serializable = externalizable || sflag;
        boolean isEnum = ((flags & ObjectStreamConstants.SC_ENUM) != 0);
        if (isEnum && suid != 0L) {
            throw new InvalidClassException(name,
                    "enum descriptor has non-zero serialVersionUID: " + suid);
        }
        int numFields = bin.readShort();
        if (isEnum && numFields != 0) {
            throw new InvalidClassException(name,
                    "enum descriptor has non-zero field count: " + numFields);
        }
        for (int i = 0; i < numFields; i++) {
            char tcode = (char) bin.readByte();
            String fname = bin.readUTF();
            String signature = ((tcode == 'L') || (tcode == '[')) ? readTypeString() : new String(new char[] { tcode });
        }
        skipCustomData();
        readClassDesc();

        objectList.add(name);

        ColorPrint.println("* " + name + " / " + suid + " / " + numFields, ColorPrint.MAGENTA);
    }

    private String readTypeString() throws IOException {
        byte tc = bin.peekByte();
        switch (tc) {
            case TC_NULL:
                return (String) readNull();

            case TC_REFERENCE:
                return checkReference();

            case TC_STRING:
            case TC_LONGSTRING:
                return readString();

            default:
                throw new StreamCorruptedException(
                        String.format("invalid type code: %02X", tc));
        }
    }

    private String readString() throws IOException {
        String str = "";
        byte tc = bin.readByte();
        switch (tc) {
            case TC_STRING:
                str = bin.readUTF();
                break;

            case TC_LONGSTRING:
                //str = bin.readLongUTF();
                break;

            default:
                throw new StreamCorruptedException(
                        String.format("invalid type code: %02X", tc));
        }
        objectList.add(String.class.getName());
        return str;
    }

    private Object readNull() throws IOException {
        if (bin.readByte() != TC_NULL) {
            throw new InternalError();
        }
        return null;
    }

    private void skipCustomData() throws IOException {
        for (;;) {
            if (bin.getBlockDataMode()) {
                bin.skipBlockData();
                bin.setBlockDataMode(false);
            }
            switch (bin.peekByte()) {
                case TC_BLOCKDATA:
                case TC_BLOCKDATALONG:
                    bin.setBlockDataMode(true);
                    break;

                case TC_ENDBLOCKDATA:
                    bin.readByte();
                    return;

                default:
                    return;
            }
        }
    }

    private void stackReference() {
        parentObjectNumberStack.addFirst(nowObjectNumber);
    }

    private void addReferenceToObject(int from, int to) {
        while (to >= referencesList.size()) {
            referencesList.add(new ArrayList<>());
        }

        List<Integer> references = referencesList.get(to);
        if (!references.contains(from)) {
            references.add(from);
        }
    }

    private void checkReferenceDepth() throws UnsafeStreamException {

        System.out.println(referencesList);

        for (int i = 0; i < referencesList.size(); i++) {
            if (referencesList.get(i).size() > 0) {
                System.out.print(String.format("%02x", i) + "-");
                try {
                    countReference(i);
                } catch (UnsafeStreamException e) {
                    System.out.println("");
                    ColorPrint.println("* Object reference too complex. (it may be a deserialization DoS attack)", ColorPrint.RED);

                    throw new UnsafeStreamException("* Object reference too complex. (it may be a deserialization DoS attack)");
                }
                System.out.println("");
                ColorPrint.println("* Object ID: " + i + ", Reference count per Object: " + referenceCount, ColorPrint.MAGENTA);
                System.out.println("");
                referenceCount = 0;
            }
        }
        ColorPrint.println("* Object reference is safe.", ColorPrint.CYAN);
    }

    private void countReference(int position) throws UnsafeStreamException {
        if (referenceCount > REFERENCE_MAX) {
            throw new UnsafeStreamException();
        }

        if (referencesList.size() >= position) {
            List<Integer> references = referencesList.get(position);
            for (int reference : references) {
                if (reference != 0) {
                    System.out.print(String.format("%02x", reference) + "-");
                    referenceDepth++;
                    referenceCount++;
                    countReference(reference);
                }
            }
        }
        if (referenceDepth > 0) {
            System.out.print("/");
        }
        referenceDepth = 0;
    }
}
