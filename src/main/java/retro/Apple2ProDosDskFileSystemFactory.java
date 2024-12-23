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
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Apple2ProDosDskFileSystemFactory implements GFileSystemFactoryByteProvider<Apple2ProDosDskFileSystem>, GFileSystemProbeByteProvider {

    public static final int TRACKS = 35;
    public static final int SECTORS_PER_TRACK = 16;
    public static final int BLOCKS_PER_TRACK = SECTORS_PER_TRACK / 2;
    public static final int SECTOR_SIZE = 256;
    public static final int BLOCK_SIZE = SECTOR_SIZE * 2;
    public static final int DISK_IMAGE_SIZE = TRACKS * SECTORS_PER_TRACK * SECTOR_SIZE;

    private boolean isProDosOrder;

    @Override
    public boolean probe(ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
    		throws IOException {

        if (provider.length() != DISK_IMAGE_SIZE) return false;

        BinaryReader reader = new BinaryReader(provider, true);

        int numberOfBootSectors = reader.readNextUnsignedByte();

        if (numberOfBootSectors != 1) Msg.info(this, "Number of boot sectors is " + numberOfBootSectors + ", expected 1.");

        // Offsets of the ProDOS "key block" for ProDOS and DOS 3 ordering
        int[] keyBlockOffsets = {
            BLOCK_SIZE * 2, // ProDOS ordering
            SECTOR_SIZE * 11 // DOS 3 ordering
        };

        // Loop through each key block offset
        for (int offset : keyBlockOffsets) {
            reader.setPointerIndex(offset);

            // first come two pointers to previous and next directory blocks
            int kbPrevDirBlockNum = reader.readNextUnsignedShort(); // always 0?
            int kbNextDirBlockNum = reader.readNextUnsignedShort(); // always 3?
            
            // next come all of the volume directory headers for each file, directory, etc
            // the first one is for the volume itself
            int vdhStorageTypeAndNameLength = reader.readNextUnsignedByte();
            int vdhStorageTYpe = vdhStorageTypeAndNameLength >> 4;
            int vdhNameLength = vdhStorageTypeAndNameLength & 0x0f;
            byte[] vdhName = reader.readNextByteArray(15);
            int r1 = reader.readNextUnsignedShort(); // reserved, should be zeros
            long modTime = reader.readNextUnsignedInt();
            int lowerCaseFlags = reader.readNextUnsignedShort();
            long createTime = reader.readNextUnsignedInt();
            int versionMinVersion = reader.readNextUnsignedShort(); // one int with two meanings or one value per byte?
            int accessFlags = reader.readNextUnsignedByte();
            int directoryEntryLength = reader.readNextUnsignedByte(); // usually $27 (39)
            int entriesPerDirBlock = reader.readNextUnsignedByte(); // usually $200/$27 = $0d
            int numActiveEntriesInVolumeDir = reader.readNextUnsignedShort();
            int volumeBitmapStartBlock = reader.readNextUnsignedShort();
            int totalBlocksInVolume = reader.readNextUnsignedShort();

            if (kbPrevDirBlockNum == 0 && kbNextDirBlockNum == 3 &&
                    vdhStorageTYpe == 0x0f &&
                    vdhNameLength >= 1 && vdhNameLength <= 15 &&
                    isValidVolumeName(vdhName, vdhNameLength) &&
                    r1 == 0 &&
                    directoryEntryLength == 39 &&
                    entriesPerDirBlock == 13 &&
                    volumeBitmapStartBlock < TRACKS * BLOCKS_PER_TRACK &&
                    totalBlocksInVolume == TRACKS * BLOCKS_PER_TRACK
            ) {
                isProDosOrder = (offset == keyBlockOffsets[0]);
                String ordering = (offset == keyBlockOffsets[0]) ? "ProDOS" : "DOS 3";
                // Msg.info(this, "ProDOS volume directory header key block found. Ordering: " + ordering);
                return true;
            }
        }

        return false;
    }

    private boolean isValidVolumeName(byte[] vdhName, int vdhNameLength) {
        // check if the name is conformant: A-Z 1st char, then 0 or more of A-Z or 0-9 or ".", then remaining bytes MUST be null
        if (vdhName[0] < 'A' || vdhName[0] > 'Z') return false;
        for (int i = 1; i < vdhNameLength; i++) {
            if (vdhName[i] < 'A' && vdhName[i] > 'Z' &&
                vdhName[i] < '0' && vdhName[i] > '9' &&
                vdhName[i] != '.' &&
                vdhName[i] != '-' // not in the spec but used in my prodos disk images
            ) return false;
        }
        for (int i = vdhNameLength; i < 15; i++) {
            if (vdhName[i] != 0) return false;
        }
        return true;
    }

    @Override
    public GFileSystem create(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {

        Apple2ProDosDskFileSystem fs = new Apple2ProDosDskFileSystem(fsFSRL, provider, isProDosOrder);
        fs.mount(monitor);
        return fs;
    }
}
