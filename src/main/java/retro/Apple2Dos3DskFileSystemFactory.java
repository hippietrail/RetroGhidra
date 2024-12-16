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
import java.util.stream.IntStream;

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

public class Apple2Dos3DskFileSystemFactory implements GFileSystemFactoryByteProvider<Apple2Dos3DskFileSystem>, GFileSystemProbeByteProvider {

    public static final int TRACKS = 35;
    public static final int SECTORS_PER_TRACK = 16;
    public static final int SECTOR_SIZE = 256;
    public static final int DISK_IMAGE_SIZE = TRACKS * SECTORS_PER_TRACK * SECTOR_SIZE;

    @Override
    public boolean probe(ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

        if (provider.length() != DISK_IMAGE_SIZE) return false;

        // DOS 3 directory is on Track #17 Sector #0 - Sector #0 is in the same place for both .do and .po orderings
        int vtocOffset = SECTOR_SIZE * SECTORS_PER_TRACK * 17;

        BinaryReader reader = new BinaryReader(provider, true);

        int numberOfBootSectors = reader.readNextUnsignedByte();

        if (numberOfBootSectors != 1) Msg.info(this, "Number of boot sectors is " + numberOfBootSectors + ", expected 1.");

        reader.setPointerIndex(vtocOffset);
        
        int u1 = reader.readNextUnsignedByte(); // unused - always zero? NO!
        int nextCatalogSectorTrack = reader.readNextUnsignedByte(); // always 17? probably
        int nextCatalogSectorSector = reader.readNextUnsignedByte(); // always 15? NO
        int dosVersion = reader.readNextUnsignedByte(); // always 2 or 3? NO
        int u2 = reader.readNextUnsignedShort(); // unused x 2 - always zero? NO!
        int diskVolumeNumber = reader.readNextUnsignedByte();
        byte[] u3 = reader.readNextByteArray(32); // usnused - all always zero? NO! have seen [0] = -2
        int maxTrackSectorPairs = reader.readNextUnsignedByte(); // should be 122
        int u4 = reader.readNextUnsignedShort(); // unused x 2 - always zero?

        if (nextCatalogSectorTrack == 17 &&
			nextCatalogSectorSector < SECTORS_PER_TRACK &&
			// (dosVersion == 2 || dosVersion == 3) &&
			diskVolumeNumber < 255 &&
            // u3 test how? IntStream?
			IntStream.range(1, u3.length).allMatch(i -> u3[i] == 0) &&
            maxTrackSectorPairs == 122
        ) {
            Msg.info(this, "DOS 3 VTOC found");
			return true;
		}
        
        // Msg.info(this, String.format("u1 %d, next cat sect track %d, next cat sect sector %d, dos version %d, u2 %d, volume number %d",
    	// 	u1,
    	// 	nextCatalogSectorTrack, nextCatalogSectorSector,
    	// 	dosVersion,
    	// 	u2,
    	// 	diskVolumeNumber));
        
        // if it looks like a VTOC, we still have to scan through the sectors to observe
        // the order of nextCatalogSectorSector's values - this tell us .do ordering vs .po

        return false;
    }

    @Override
    public GFileSystem create(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {

        Apple2Dos3DskFileSystem fs = new Apple2Dos3DskFileSystem(fsFSRL, provider);
        fs.mount(monitor);
        return fs;
    }
    
}
