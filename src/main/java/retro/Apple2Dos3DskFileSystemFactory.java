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

    private boolean isDos3Order;

    @Override
    public boolean probe(ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

        if (provider.length() != DISK_IMAGE_SIZE) return false;

        // DOS 3 directory is on Track #17 Sector #0 - Sector #0 is in the same place for both .do and .po orderings
        // VTOC is Volume Table of Contents
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
        // int u4 = reader.readNextUnsignedShort(); // unused x 2 - always zero?
        byte[] u4 = reader.readNextByteArray(8);
        int lastTrackWithAllocatedSectors = reader.readNextUnsignedByte();
        int directionOfTrackAllocation = reader.readNextByte(); // always -1 or 1
        int u5 = reader.readNextUnsignedShort(); // unused x 2 - always zero?
        int numberOfTracks = reader.readNextUnsignedByte(); // usually 35, 40, or 50
        int numberOfSectors = reader.readNextUnsignedByte(); // usually 13, 16, or 32
        int numberOfBytesPerSector = reader.readNextUnsignedShort(); // always 256?
        // the reamainder of the sector consists of 4-byte free sector bitmaps, 1 for each track

        if (nextCatalogSectorTrack == 17 &&
			nextCatalogSectorSector < SECTORS_PER_TRACK &&
			// (dosVersion == 2 || dosVersion == 3) &&
			diskVolumeNumber < 255 &&
            IntStream.range(1, u3.length).allMatch(i -> u3[i] == 0) &&
            maxTrackSectorPairs == 122 &&
            IntStream.range(0, u4.length).allMatch(i -> u4[i] == 0) &&
            // lastTrackWithAllocatedSectors < TRACKS && // loderunner data disk: 255
            (directionOfTrackAllocation == -1 || directionOfTrackAllocation == 1) &&
            u5 == 0 &&
            (numberOfTracks == 35 || numberOfTracks == 40 || numberOfTracks == 50) &&
            // (numberOfSectors == 13 || numberOfSectors == 16 || numberOfSectors == 32) && // loderunner data disk: 15
            numberOfBytesPerSector == 256
        ) {
            // read the beginning of the next sector in the disk image to see if it's in native dos 3 sector order or not
            reader.setPointerIndex(vtocOffset + SECTOR_SIZE);
            reader.readNextUnsignedByte(); // unused - always zero? NO!
            int nextNextCatalogSectorTrack = reader.readNextUnsignedByte(); // always 17? probably
            int nextNextCatalogSectorSector = reader.readNextUnsignedByte(); // always 15? NO
            // Msg.info(this, "probe() nextCatalogSectorTrack: " + nextNextCatalogSectorTrack + ", nextCatalogSectorSector: " + nextNextCatalogSectorSector);
            if (nextNextCatalogSectorTrack == 0 && nextNextCatalogSectorSector == 0) {
                isDos3Order = true;
                // Msg.info(this, "DOS 3 VTOC found in DOS 3 ordered image");
                return true;
            } else if (nextNextCatalogSectorTrack == 17 && nextNextCatalogSectorSector == 13) {
                isDos3Order = false;
                // Msg.info(this, "DOS 3 VTOC found in ProDOS ordered image");
                return true;
            } else {
                Msg.info(this, "DOS 3 VTOC found in unknown ordered image");
            }
		}

        return false;
    }

    @Override
    public GFileSystem create(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {

        Apple2Dos3DskFileSystem fs = new Apple2Dos3DskFileSystem(fsFSRL, provider, isDos3Order);
        fs.mount(monitor);
        return fs;
    }

}
