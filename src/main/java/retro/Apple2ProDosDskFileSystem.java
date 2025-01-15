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
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RangeMappedByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class ProDosEntry {
    // standard attributes
    String name;
    long size;
    // file attributes
    int entryBlock;
    int entryNumber;
    int storageType;
    int fileType;
    int keyPointer;
    int blocksUsed;
    long eof;
    int creationDate;
    int creationTime;
    int auxType;
    int modDate;
    int modTime;
    // disk image / filesystem attributes
    String fileSystem;
    boolean isProDosOrder;

    ProDosEntry(String name, long size,
            int entryBlock, int entryNumber,
            int storageType, int fileType, int keyPointer, int blocksUsed, long eof,
            int creationDate, int creationTime,
            int auxType,
            int modDate, int modTime,
            String fileSystem, boolean isProDosOrder) {
        // standard attributes
        this.name = name;
        this.size = size;
        // file attributes
        this.entryBlock = entryBlock;
        this.entryNumber = entryNumber;
        this.storageType = storageType;
        this.fileType = fileType;
        this.keyPointer = keyPointer;
        this.blocksUsed = blocksUsed;
        this.eof = eof;
        this.creationDate = creationDate;
        this.creationTime = creationTime;
        this.auxType = auxType;
        this.modDate = modDate;
        this.modTime = modTime;
        // disk image / filesystem attributes
        this.fileSystem = fileSystem;
        this.isProDosOrder = isProDosOrder;
    }
}

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = Apple2ProDosDskFileSystem.FS_TYPE, description = "Apple II ProDOS",
        factory = Apple2ProDosDskFileSystemFactory.class)
public class Apple2ProDosDskFileSystem extends AbstractFileSystem<ProDosEntry> {

    public static final String FS_TYPE = "prodos"; // ([a-z0-9]+ only)

    // http://www.easy68k.com/paulrsm/6502/PDOS8TRM.HTM
    // https://ciderpress2.com/formatdoc/ProDOS-notes.html
    private static final int TRACKS = 35;
    private static final int SECTORS_PER_TRACK = 16;
    private static final int BLOCKS_PER_TRACK = SECTORS_PER_TRACK / 2;
    private static final int SECTOR_SIZE = 256;
    private static final int BLOCK_SIZE = SECTOR_SIZE * 2;
    private static final int DISK_IMAGE_SIZE = TRACKS * SECTORS_PER_TRACK * SECTOR_SIZE;
    private static final int VOLUME_DIRECTORY_START_BLOCK = 2;
    private static final int ENTRY_SIZE = 39;
    private static final int NUM_ENTRIES_PER_BLOCK = (BLOCK_SIZE - 2 * 2) / ENTRY_SIZE; // 2 u16 fields are prev/next block links
    private static final int ST_INACTIVE = 0x0; // deleted
    private static final int ST_SEEDLING = 0x1;
    private static final int ST_SAPLING = 0x2;
    private static final int ST_TREE = 0x3;
    private static final int ST_PASCAL = 0x4;
    private static final int ST_SUBDIRECTORY = 0xD;
    private static final int ST_SUBDIRECTORY_HEADER = 0xE;
    private static final int ST_VOLUME_DIRECTORY_HEADER = 0xF;
    private static final Map<Integer, String> STORAGE_TYPES = Map.of(
        ST_INACTIVE, "inactive file entry",
        ST_SEEDLING, "seedling file entry",
        ST_SAPLING, "sapling file entry",
        ST_TREE, "tree file entry",
        ST_PASCAL, "Pascal area",
        ST_SUBDIRECTORY, "subdirectory file entry",
        ST_SUBDIRECTORY_HEADER, "subdirectory header",
        ST_VOLUME_DIRECTORY_HEADER, "volume directory header"
    );
    private static final int[] skipTypes = new int[] {
        ST_INACTIVE,
        ST_VOLUME_DIRECTORY_HEADER,
        ST_SUBDIRECTORY_HEADER
    };
    private static final int MAX_BLOCKS_PER_SAPLING_INDEX = 256;
    private static final int MAX_BLOCKS_PER_MASTER_INDEX = 128;
    private static final int FT_TYPELESS = 0x00;
    private static final int FT_TEXT = 0x04;
    private static final int FT_BINARY = 0x06;
    private static final int FT_DIRECTORY = 0x0f;
    private static final int FT_INTEGER_BASIC = 0xfa;
    private static final int FT_APPLESOFT_BASIC = 0xfc;
    private static final int FT_RELOCATABLE = 0xfe;
    private static final int FT_SYSTEM = 0xff;
    private static final Map<Integer, String> FILE_TYPES = Map.of(
        FT_TYPELESS, "typeless",
        FT_TEXT, "ASCII text",
        FT_BINARY, "binary",
        FT_DIRECTORY, "directory",
        FT_INTEGER_BASIC, "Integer BASIC program",
        FT_APPLESOFT_BASIC, "AppleSoft BASIC program",
        FT_RELOCATABLE, "Relocatable code",
        FT_SYSTEM, "ProDOS system file"
    );

    private ByteProvider provider;
    private boolean isProDosOrder;

    /**
     * File system constructor.
     *
     * @param fsFSRL The root {@link FSRL} of the file system.
     * @param provider The file system provider.
     * @param isProDosOrder True if the file system is in ProDOS order, false if it is in DOS 3 order.
     */
    public Apple2ProDosDskFileSystem(FSRLRoot fsFSRL, ByteProvider provider, boolean isProDosOrder) {
        super(fsFSRL, FileSystemService.getInstance());
        this.provider = provider;
        this.isProDosOrder = isProDosOrder;
    }

    /**
     * Mounts (opens) the file system.
     *
     * @param monitor A cancellable task monitor.
     */
    public void mount(TaskMonitor monitor) throws IOException {
        monitor.setMessage("Opening " + Apple2ProDosDskFileSystem.class.getSimpleName() + "...");
        BinaryReader imageReader = new BinaryReader(provider, true);
        mountDirectory(monitor, imageReader, VOLUME_DIRECTORY_START_BLOCK, new String[0]);
    }

    private void mountDirectory(TaskMonitor monitor, BinaryReader imageReader, int blockNumber, String[] currentPath) throws IOException {
        if (monitor.isCancelled()) return;

        BinaryReader blockReader = new BinaryReader(new ByteArrayProvider(getBlock(imageReader, blockNumber)), true);

        int nextDirBlock = blockReader.readNextUnsignedShort();
        for (int e = 0; e < NUM_ENTRIES_PER_BLOCK; e++) {
            if (monitor.isCancelled()) return;

            long offset = 2 * 2 + e * ENTRY_SIZE; // skip prev/next block links

            int storageTypeAndNameLength = blockReader.readUnsignedByte(offset + 0x00);
            int storageType = storageTypeAndNameLength >> 4;
            int nameLength = storageTypeAndNameLength & 0x0f;

            if (Arrays.stream(skipTypes).anyMatch(type -> type == storageType)) continue;

            String name = new String(blockReader.readByteArray(offset + 0x01, nameLength));

            int fileType = blockReader.readUnsignedByte(offset + 0x10);
            int keyPointer = blockReader.readUnsignedShort(offset + 0x11);
            int blocksUsed = blockReader.readUnsignedShort(offset + 0x13);
            long eof = blockReader.readUnsignedValue(offset + 0x15, 3);
            int creationDate = blockReader.readUnsignedShort(offset + 0x18);
            int creationTime = blockReader.readUnsignedShort(offset + 0x1a);
            int auxType = blockReader.readUnsignedShort(offset + 0x1f);
            int modDate = blockReader.readUnsignedShort(offset + 0x21);
            int modTime = blockReader.readUnsignedShort(offset + 0x23);

            String[] newPath = Arrays.copyOf(currentPath, currentPath.length + 1);
            newPath[currentPath.length] = name;

            long size = -1; // documented size for directories or when otherwise unknown
            if (storageType == ST_SEEDLING || storageType == ST_SAPLING || storageType == ST_TREE) {
                size = eof;
            }

            fsIndex.storeFile(
                String.join("/", newPath),
                blockNumber * NUM_ENTRIES_PER_BLOCK + e,
                storageType == ST_SUBDIRECTORY,
                size,
                new ProDosEntry(
                    // standard attributes
                    name, size,
                    // file attributes
                    blockNumber, e,
                    storageType, fileType, keyPointer, blocksUsed, eof,
                    creationDate, creationTime,
                    auxType,
                    modDate, modTime,
                    // disk image / filesystem attributes
                    "ProDOS", isProDosOrder
                )
            );
            // should be both or neither set to directory
            if ((storageType == ST_SUBDIRECTORY) != (fileType == FT_DIRECTORY)) {
                Msg.error(this, "storageType == ST_SUBDIRECTORY != fileType == FT_DIRECTORY");
            }
            if (storageType == ST_SUBDIRECTORY) {
                mountDirectory(monitor, imageReader, keyPointer, newPath);
            }
        }
        if (nextDirBlock != 0) {
            mountDirectory(monitor, imageReader, nextDirBlock, currentPath);
        }
    }

    private String dateBytesToString(byte[] dateBytes) {
        int year = (dateBytes[1] & 0xff) >> 1;
        int month = ((dateBytes[1] & 0xff) & 1) << 3 | (dateBytes[0] & 0xff) >> 5;
        int day = dateBytes[0] & 0x1f;
        return String.format("%d-%02d-%02d", year, month, day);
    }

    private String timeBytesToString(byte[] timeBytes) {
        int hours = timeBytes[2] & 0xff;
        int minutes = timeBytes[3] & 0xff;
        return String.format("%02d:%02d", hours, minutes);
    }

    private byte[] getBlock(BinaryReader reader, int blockNum) throws IOException {
        int[] trackAndSector = getTrackAndSector(blockNum);

        byte[] sectorA = getSector(reader, trackAndSector[0], trackAndSector[1]);
        byte[] sectorB = getSector(reader, trackAndSector[0], trackAndSector[1] + 1);

        byte[] block = new byte[SECTOR_SIZE * 2];
        System.arraycopy(sectorA, 0, block, 0, SECTOR_SIZE);
        System.arraycopy(sectorB, 0, block, SECTOR_SIZE, SECTOR_SIZE);
        return block;
    }

    private byte[] getSector(BinaryReader reader, int track, int logicalSector) throws IOException {
        long offset = logicalTrackAndSectorToOffset(track, logicalSector);
        // Msg.info(this, "offset: 0x" + Long.toHexString(offset));
        byte[] buffer = reader.readByteArray(offset, SECTOR_SIZE);
        return buffer;
    }

    private long blockNumberToOffset(int blockNum) {
        int[] ts = getTrackAndSector(blockNum);
        return logicalTrackAndSectorToOffset(ts[0], ts[1]);
    }

    private long[] blockNumberToOffsets(int blockNum) {
        int[] ts = getTrackAndSector(blockNum);
        return new long[] {
            logicalTrackAndSectorToOffset(ts[0], ts[1]),
            logicalTrackAndSectorToOffset(ts[0], ts[1] + 1)
        };
    }

    private long logicalTrackAndSectorToOffset(int track, int logicalSector) {
        int imageSector = getDiskImageSectorNum(logicalSector); // logical to physical
        long offset = (long) track * SECTORS_PER_TRACK * SECTOR_SIZE + imageSector * SECTOR_SIZE;
        return offset;
    }

    private int[] getTrackAndSector(int blockNum) {
        return new int[] { blockNum / BLOCKS_PER_TRACK, (blockNum % BLOCKS_PER_TRACK) * 2 };
    }

    // logical to physical
    private int getDiskImageSectorNum(int sector) {
        if (!isProDosOrder && sector != 0 && sector != 15) sector = 15 - sector;
        return sector;
    }

    @Override
    public void close() throws IOException {
        refManager.onClose();
        fsIndex.clear();
        if (provider != null) {
            provider.close();
            provider = null;
        }
    }

    @Override
    public boolean isClosed() {
        return provider == null;
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
            throws IOException, CancelledException {

        ProDosEntry metadata = fsIndex.getMetadata(file);
        if (metadata == null) return null;

        if (metadata.storageType == ST_SEEDLING) {
            RangeMappedByteProvider seedling = new RangeMappedByteProvider(provider, file.getFSRL());
            long[] dataSectors = blockNumberToOffsets(metadata.keyPointer);

            seedling.addRange(dataSectors[0], SECTOR_SIZE);
            seedling.addRange(dataSectors[1], SECTOR_SIZE);
            return seedling;
        } else if (metadata.storageType == ST_SAPLING) {
            RangeMappedByteProvider sapling = new RangeMappedByteProvider(provider, file.getFSRL());
            long indexBlockSectors[] = blockNumberToOffsets(metadata.keyPointer);

            for (int i = 0; i < metadata.blocksUsed; i++) {
                int b = (provider.readByte(indexBlockSectors[1] + i) & 0xff) << 8;
                b |= (provider.readByte(indexBlockSectors[0] + i) & 0xff);
                if (b == 0) {
                    sapling.addSparseRange(BLOCK_SIZE);
                } else {
                    long[] dataBlockSectors = blockNumberToOffsets(b);
                    sapling.addRange(dataBlockSectors[0], SECTOR_SIZE);
                    sapling.addRange(dataBlockSectors[1], SECTOR_SIZE);
                }
                if (sapling.length() >= metadata.eof) return sapling;
            }
            throw new IOException("Size: " + sapling.length() + ", Expected: " + metadata.eof);
        } else if (metadata.storageType == ST_TREE) {
            RangeMappedByteProvider tree = new RangeMappedByteProvider(provider, file.getFSRL());
            long masterIndexBlockSectors[] = blockNumberToOffsets(metadata.keyPointer);

            for (int i = 0; i < MAX_BLOCKS_PER_MASTER_INDEX; i++) {
                int b = (provider.readByte(masterIndexBlockSectors[1] + i) & 0xff) << 8;
                b |= (provider.readByte(masterIndexBlockSectors[0] + i) & 0xff);
                if (b == 0) {
                    tree.addSparseRange(MAX_BLOCKS_PER_SAPLING_INDEX * BLOCK_SIZE);
                } else {
                    long[] indexBlockSectors = blockNumberToOffsets(b);
                    for (int j = 0; j < MAX_BLOCKS_PER_SAPLING_INDEX; j++) {
                        b = (provider.readByte(indexBlockSectors[1] + j) & 0xff) << 8;
                        b |= (provider.readByte(indexBlockSectors[0] + j) & 0xff);
                        if (b == 0) {
                            tree.addSparseRange(BLOCK_SIZE);
                        } else {
                            long[] dataBlockSectors = blockNumberToOffsets(b);
                            tree.addRange(dataBlockSectors[0], SECTOR_SIZE);
                            tree.addRange(dataBlockSectors[1], SECTOR_SIZE);
                        }
                        if (tree.length() >= metadata.eof) return tree;
                    }
                }
                if (tree.length() >= metadata.eof) return tree;
            }
            throw new IOException("Size: " + tree.length() + ", Expected: " + metadata.eof);
        } else {
            throw new IOException("Unknown storage type: " + metadata.storageType);
        }
    }

    public ProDosEntry getMetadata(GFile file) {
        return fsIndex.getMetadata(file);
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        ProDosEntry metadata = fsIndex.getMetadata(file);
        FileAttributes result = new FileAttributes();
        if (metadata != null) {
            // standard attributes
            result.add(FileAttributeType.NAME_ATTR, metadata.name);
            result.add(FileAttributeType.SIZE_ATTR, metadata.size);
            // Date and time (two 16-bit values):
            // YYYYYYY MMMM DDDDD
            // 000 HHHHH 00 MMMMMM
            int y = metadata.modDate >> 9;
            y = y < 40 ? 2000 + y : 1900 + y;
            int mon = (metadata.modDate >> 5) & 0x0f;
            int d = metadata.modDate & 0x1f;
            int h = metadata.modTime >> 8;
            int min = metadata.modTime & 0x3f;
            result.add(FileAttributeType.MODIFIED_DATE_ATTR, new Date(y - 1900, mon, d, h, min));
            y = metadata.creationDate >> 9;
            y = y < 40 ? 2000 + y : 1900 + y;
            mon = (metadata.creationDate >> 5) & 0x0f;
            d = metadata.creationDate & 0x1f;
            h = metadata.creationTime >> 8;
            min = metadata.creationTime & 0x3f;
            result.add(FileAttributeType.CREATE_DATE_ATTR, new Date(y - 1900, mon, d, h, min));
            // file attributes
            result.add("Entry Block/Number", metadata.entryBlock + "/" + metadata.entryNumber);
            result.add("Storage Type", typeToString(STORAGE_TYPES, metadata.storageType));
            result.add("File Type", typeToString(FILE_TYPES, metadata.fileType));
            result.add("Key Pointer", metadata.keyPointer);
            result.add("Blocks Used", metadata.blocksUsed);
            result.add("Aux Type", String.format("0x%04x", metadata.auxType));

            // TODO PR 7062 not yet available as of Ghidra 11.2.1
            // result.add(FileAttributeType.FILENAME_EXT_OVERRIDE, "exe");

            // disk image / filesystem attributes
            result.add("Filesystem", metadata.fileSystem);
            result.add("Ordering", metadata.isProDosOrder ? "ProDOS" : "DOS 3");
        }
        return result;
    }

    private static String typeToString(Map<Integer, String> map, int type) {
        String result = String.format("0x%02x", type);
        if (map.containsKey(type)) result += " (" + map.get(type) + ")";
        return result;
    }

    public static String fileTypeToString(int fileType) {
        return typeToString(FILE_TYPES, fileType);
    }

}
