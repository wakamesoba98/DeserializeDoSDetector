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

package net.wakamesoba98.deserializedosdetector;

import net.wakamesoba98.deserializedosdetector.util.ColorPrint;
import net.wakamesoba98.deserializedosdetector.io.DeserializeDoSDetector;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Scanner;

public class Main {

    private static void printHeapMemory() {
        Runtime runtime = Runtime.getRuntime();
        int mega = (int) Math.pow(1024, 2);
        ColorPrint.println("* Max JVM heap memory: " + runtime.maxMemory() / mega + " MB", ColorPrint.MAGENTA);
    }

    private static void promptEnterKey() {
        System.out.println("Press \"ENTER\" to continue...");
        Scanner scanner = new Scanner(System.in);
        scanner.nextLine();
    }

    private static void check(String fileName) {
        FileInputStream in = null;
        try {
            File file = new File(fileName);
            in = new FileInputStream(file);
            DeserializeDoSDetector checker = new DeserializeDoSDetector(in);
            checker.check();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) {
        printHeapMemory();
        promptEnterKey();
        check("/path/to/serialized_object.bin");
    }
}
