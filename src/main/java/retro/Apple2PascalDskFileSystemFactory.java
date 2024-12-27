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

public class Apple2PascalDskFileSystemFactory implements GFileSystemFactoryByteProvider<Apple2PascalDskFileSystem>, GFileSystemProbeByteProvider {

    public static final int TRACKS = 35;
    public static final int SECTORS_PER_TRACK = 16;
    public static final int SECTOR_SIZE = 256;
    public static final int DISK_IMAGE_SIZE = TRACKS * SECTORS_PER_TRACK * SECTOR_SIZE;

    @Override
    public boolean probe(ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException {

        if (provider.length() != DISK_IMAGE_SIZE) return false;

        BinaryReader reader = new BinaryReader(provider, true);

        reader.setPointerIndex(SECTOR_SIZE * 11); // all the images I have are in DOS 3 order

        int zero1 = reader.readNextUnsignedShort();
        int six = reader.readNextUnsignedShort();
        int zero2 = reader.readNextUnsignedShort();
        int fileNameLen = reader.readNextUnsignedByte();

        return zero1 == 0 && six == 6 && zero2 == 0 && fileNameLen >= 1 && fileNameLen <= 7;
    }

    @Override
    public GFileSystem create(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {

        Apple2PascalDskFileSystem fs = new Apple2PascalDskFileSystem(fsFSRL, provider);
        fs.mount(monitor);
        return fs;
    }
}
