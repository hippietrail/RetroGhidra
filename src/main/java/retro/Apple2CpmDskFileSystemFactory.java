/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package retro;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Apple2CpmDskFileSystemFactory implements GFileSystemFactoryByteProvider<Apple2CpmDskFileSystem>, GFileSystemProbeByteProvider {

    public static final int TRACKS = 35;
    public static final int SECTORS_PER_TRACK = 16;
    public static final int SECTOR_SIZE = 256;
    public static final int DISK_IMAGE_SIZE = TRACKS * SECTORS_PER_TRACK * SECTOR_SIZE;

    @Override
    public boolean probe(ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException {

        if (provider.length() != DISK_IMAGE_SIZE) return false;

        BinaryReader reader = new BinaryReader(provider, true);

        reader.setPointerIndex(3 * SECTORS_PER_TRACK * SECTOR_SIZE);

        // sector 0 is sector 0 no matter the order
        // so this only checks for cp/m directory at track 3 sector 0
        // and does not check for dos 3 or pro dos sector ordering

        int userNum = reader.readNextUnsignedByte();
        int fileNameFirstChar = reader.readNextUnsignedByte();
        if (userNum == 0 || userNum == 0xe5) {
            // 1 to 8 [A-Z] followed by 8-len ' '
            if (fileNameFirstChar >= 'A' && fileNameFirstChar <= 'Z') return true;
        } else if (userNum == 0x1f) {
            // cp/am has a special first dir entry in lower case
            if (fileNameFirstChar == 'c') return true;
        }

        return false;
    }

    @Override
    public GFileSystem create(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {

        Apple2CpmDskFileSystem fs = new Apple2CpmDskFileSystem(fsFSRL, provider);
        fs.mount(monitor);
        return fs;
    }
}
