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
import ghidra.app.util.bin.RangeMappedByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class Dos3Entry {
    // standard attributes
    String name;
    long size;
    // file attributes
    int firstTslsTrack; // TSLS = "Track/Sector List Sector"
    int firstTslsSector;
    int fileType;
    boolean isLocked;
    int lenInSectors;
    int entryTrack;
    int entrySector;
    int entryNumber;
    // disk image / filesystem attributes
    String fileSystem;
    boolean isDos3Order;

    Dos3Entry(String name, long size,
            int firstTslsTrack, int firstTslsSector,
            int fileType, boolean isLocked, int lenInSectors,
            int entryTrack, int entrySector, int entryNumber,
            String fileSystem, boolean isDos3Order) {
        // standard attributes
        this.name = name;
        this.size = size;
        // file attributes
        this.firstTslsTrack = firstTslsTrack;
        this.firstTslsSector = firstTslsSector;
        this.fileType = fileType;
        this.isLocked = isLocked;
        this.lenInSectors = lenInSectors;
        this.entryTrack = entryTrack;
        this.entrySector = entrySector;
        this.entryNumber = entryNumber;
        // disk image / filesystem attributes
        this.fileSystem = fileSystem;
        this.isDos3Order = isDos3Order;
    }
}

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = Apple2Dos3DskFileSystem.FS_TYPE, description = "Apple II DOS 3.3",
        factory = Apple2Dos3DskFileSystemFactory.class)
public class Apple2Dos3DskFileSystem extends AbstractFileSystem<Dos3Entry> {

    public static final String FS_TYPE = "dos3"; // ([a-z0-9]+ only)

    // http://justsolve.archiveteam.org/wiki/Apple_DOS_file_system
    // https://ciderpress2.com/formatdoc/DOS-notes.html
    // https://mirrors.apple2.org.za/ftp.apple.asimov.net/documentation/misc/apple2_disk_format.doc.txt
    private static final int TRACKS = 35;
    private static final int SECTORS_PER_TRACK = 16;
    private static final int SECTOR_SIZE = 256;
    private static final int SECTORS_PER_TRACK_SHIFT = 4;
    private static final int SECTOR_SIZE_SHIFT = 8;
    private static final int DISK_IMAGE_SIZE = TRACKS * SECTORS_PER_TRACK * SECTOR_SIZE;
    private static final int CATALOG_TRACK = 17;
    private static final int ENTRIES_PER_SECTOR = 7;
    private static final int ENTRIES_START_OFFSET = 0x0b;
    private static final int UNUSED = 0;
    private static final int DELETED = 0xff;
    private static final int FILE_NAME_LENGTH = 30;
    private static final int ENTRY_SIZE = 35;
    // file types look like bits that could be ORed together, but they can't
    // we can convert from an array index to the bit value though as per the comment fields below:
    private static final String[] FILE_TYPES = {
        "TEXT",                     // 00 * 0
        "INTEGER BASIC",            // 01 0 1
        "APPLESOFT BASIC",          // 02 1 2
        "BINARY",                   // 04 2 3
        "S type file",              // 08 3 4
        "RELOCATABLE object module",// 10 4 5
        "a type file",              // 20 5 6
        "b type file",              // 40 6 7
    };

    private ByteProvider provider;
    private boolean isDos3Order;

    /**
     * File system constructor.
     *
     * @param fsFSRL The root {@link FSRL} of the file system.
     * @param provider The file system provider.
     * @param isDos3Order True if the disk image is in DOS 3 sector order, false if it is in ProDOS sector order.
     */
    public Apple2Dos3DskFileSystem(FSRLRoot fsFSRL, ByteProvider provider, boolean isDos3Order) {
        super(fsFSRL, FileSystemService.getInstance());
        this.provider = provider;
        this.isDos3Order = isDos3Order;
    }

    /**
     * Mounts (opens) the file system.
     *
     * @param monitor A cancellable task monitor.
     */
    public void mount(TaskMonitor monitor) throws IOException {
        monitor.setMessage("Opening " + Apple2Dos3DskFileSystem.class.getSimpleName() + "...");

        BinaryReader reader = new BinaryReader(provider, true);

        // read the VTOC and then loop over the remaining sectors in the track
        final int vtocOffset = SECTOR_SIZE * SECTORS_PER_TRACK * CATALOG_TRACK;
        reader.setPointerIndex(vtocOffset);

        reader.readNextUnsignedByte();                                      // unused
        final int firstCatalogSectorTrack = reader.readNextUnsignedByte();  // always 17
        final int firstCatalogSectorSector = reader.readNextUnsignedByte(); // NOT always 15

        int catTrack = firstCatalogSectorTrack;
        int catSector = firstCatalogSectorSector;

        int gix = 0; // unique index for Ghidra

        while (catTrack != 0) {
            if (monitor.isCancelled()) break;
            if (catTrack != CATALOG_TRACK) throw new IOException("Unexpected track number in catalog: " + catTrack);
            if (catSector < 0 || catSector >= SECTORS_PER_TRACK) throw new IOException("Unexpected sector number in catalog: " + catSector);

            final int adjustedSector = isDos3Order || catSector == 0 || catSector == SECTORS_PER_TRACK - 1
                ? catSector
                : 15 - catSector;

            final int offset = SECTOR_SIZE * SECTORS_PER_TRACK * catTrack + SECTOR_SIZE * adjustedSector;

            reader.setPointerIndex(offset + 1); // skip unused first byte
            int nextCatalogSectorTrack = reader.readNextUnsignedByte();
            int nextCatalogSectorSector = reader.readNextUnsignedByte();

            // in a catalog sector the entries start at offset 0x0b
            reader.setPointerIndex(offset + ENTRIES_START_OFFSET);
            for (int i = 0; i < ENTRIES_PER_SECTOR; i++) {
                int firstTslSectorTrack = reader.readNextUnsignedByte();
                int firstTslSectorSector = reader.readNextUnsignedByte();
                if (firstTslSectorTrack == UNUSED || firstTslSectorTrack == DELETED) {
                    reader.setPointerIndex(reader.getPointerIndex() + ENTRY_SIZE - 1);
                    continue;
                }

                int fileTypeAndFlags = reader.readNextUnsignedByte();
                boolean isLocked = (fileTypeAndFlags & 0x80) != 0;
                int fileType = fileTypeAndFlags & 0x7f;

                byte[] rawName = reader.readNextByteArray(FILE_NAME_LENGTH);
                // strip the high bit off each byte
                for (int j = 0; j < rawName.length; j++) rawName[j] &= 0x7f;
                String name = new String(rawName, "ASCII").trim();
                int lengthInSectors = reader.readNextUnsignedShort();

                int size = lengthInSectors * SECTOR_SIZE;

                fsIndex.storeFile(
                    name,
                    gix++,
                    false,
                    size,
                    new Dos3Entry(
                        // standard attributes
                        name, size,
                        // file attributes
                        firstTslSectorTrack, firstTslSectorSector,
                        fileType, isLocked, lengthInSectors,
                        catTrack, catSector, i,
                        // disk image / filesystem attributes
                        "DOS 3", isDos3Order
                    )
                );
            }

            catTrack = nextCatalogSectorTrack;
            catSector = nextCatalogSectorSector;
        }
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

        Dos3Entry metadata = fsIndex.getMetadata(file);
        if (metadata == null) return null;

        BinaryReader r = new BinaryReader(provider, true);
        RangeMappedByteProvider rmbp = new RangeMappedByteProvider(provider, file.getFSRL());

        int tslt = metadata.firstTslsTrack; // T=0/255 are special
        int tsls = metadata.firstTslsSector;

        int sectorCount = metadata.lenInSectors;

        // the outer loop is like a linked list terminated by tslt == 0
        while (tslt != 0) {
            if (!isDos3Order && tsls != 0 && tsls != 15) tsls = 15 - tsls;
            long tslOff = ((tslt << SECTORS_PER_TRACK_SHIFT) + tsls) << SECTOR_SIZE_SHIFT;

            r.setPointerIndex(tslOff + 1); // skip unused first byte
            int nextTslTrack = r.readNextUnsignedByte(); // T=0 indicates end of list
            int nextTslSector = r.readNextUnsignedByte();

            // skip 2 reserved bytes; read short "sector offset in file of the first sector defined by this list"; skip 5 reserved bytes
            r.readNextUnsignedShort();
            int firstDataSectorOffset = r.readNextUnsignedShort(); // 0 unless file is really big (> 122 * 256 bytes)
            r.setPointerIndex(r.getPointerIndex() + 5);

            // the inner loop is like an array of 122 entries
            // one track/sector list sector can have up to 122 entries after the 12-byte header
            for (int i = 0; i < 122; i++) {
                int t = r.readNextUnsignedByte();
                int s = r.readNextUnsignedByte();
                if (t == 0) {
                    rmbp.addSparseRange(SECTOR_SIZE);
                } else {
                    if (!isDos3Order && s != 0 && s != 15) s = 15 - s;
                    long dataOff = ((t << SECTORS_PER_TRACK_SHIFT) + s) << SECTOR_SIZE_SHIFT;
                    rmbp.addRange(dataOff, SECTOR_SIZE);
                }
                sectorCount--;
                if (sectorCount == 0) return rmbp;
            }

            tslt = nextTslTrack;
            tsls = nextTslSector;
        }

        return rmbp;
    }

    public Dos3Entry getMetadata(GFile file) {
        return fsIndex.getMetadata(file);
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        Dos3Entry metadata = fsIndex.getMetadata(file);
        FileAttributes result = new FileAttributes();
        if (metadata != null) {
            // standard attributes
            result.add(FileAttributeType.NAME_ATTR, metadata.name);
            result.add(FileAttributeType.SIZE_ATTR, metadata.size);
            // file attributes
            result.add("Filetype", filetypeToString(metadata.fileType));
            result.add("Locked", metadata.isLocked);
            result.add("Length in sectors", metadata.lenInSectors);
            result.add("Entry Track/Sector/Number", metadata.entryTrack + "/" + metadata.entrySector + "/" + metadata.entryNumber);
            // disk image / filesystem attributes
            result.add("Filesystem", metadata.fileSystem);
            result.add("Ordering", metadata.isDos3Order ? "DOS 3" : "ProDOS");

            // TODO PR 7062 not yet available as of Ghidra 11.2.1
            // result.add(FileAttributeType.FILENAME_EXT_OVERRIDE, "exe");
        }
        return result;
    }

    public static String filetypeToString(int fileType) {
        int index = fileType == 0 ? 0 : Integer.numberOfTrailingZeros(fileType) + 1;
        String result = String.format("0x%02x", fileType);
        if (index < FILE_TYPES.length && FILE_TYPES[index] != null) {
            result += " (" + FILE_TYPES[index] + ")";
        }
        return result;
    }

}
