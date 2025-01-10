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
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class D80Entry {
    public final String name;
    public final long size;

    public final int filetype;
    public final int track;
    public final int sector;
    public final long offset;

    D80Entry(String name, long size, int filetype, int track, int sector, long offset) {
        this.name = name;
        this.size = size;

        this.filetype = filetype;

        this.track = track;
        this.sector = sector;
        this.offset = offset;
    }
}

/**
 * {@link FileSystem} for Commodore D80 disk images.
 * 
 * @see <a href="https://vice-emu.sourceforge.io/vice_16.html#SEC423">VICE Manual - 16  The emulator file formats / 16.9 The D80 disk image format</a>
 */
@FileSystemInfo(type = "d80", // ([a-z0-9]+ only)
        description = "Commodore D80 disk image", factory = CommodoreD80FileSystemFactory.class)
public class CommodoreD80FileSystem extends AbstractFileSystem<D80Entry> {

    // tracks start at 1 so use thus: trackOffset = trackOffsets[trackNumber - 1]
    private static final long[] D80_TRACK_OFFSETS = new long[] {
        // 29 sectors per track (39)
        0x00000, 0x01D00, 0x03A00, 0x05700, 0x07400, 0x09100, 0x0AE00, 0x0CB00, 0x0E800, 0x10500,
        0x12200, 0x13F00, 0x15C00, 0x17900, 0x19600, 0x1B300, 0x1D000, 0x1ED00, 0x20A00, 0x22700,
        0x24400, 0x26100, 0x27E00, 0x29B00, 0x2B800, 0x2D500, 0x2F200, 0x30F00, 0x32C00, 0x34900,
        0x36600, 0x38300, 0x3A000, 0x3BD00, 0x3DA00, 0x3F700, 0x41400, 0x43100, 0x44E00,
        // 27 sectors per track (14)
        0x46B00, 0x48600, 0x4A100, 0x4BC00, 0x4D700, 0x4F200, 0x50D00, 0x52800, 0x54300, 0x55E00,
        0x57900, 0x59400, 0x5AF00, 0x5CA00,
        // 25 sectors per track (11)
        0x5E500, 0x5FE00, 0x61700, 0x63000, 0x64900, 0x66200, 0x67B00, 0x69400, 0x6AD00, 0x6C600,
        0x6DF00,
        // 23 sectors per track (13)
        0x6F800, 0x70F00, 0x72600, 0x73D00, 0x75400, 0x76B00, 0x78200, 0x79900, 0x7B000, 0x7C700,
        0x7DE00, 0x7F500, 0x80C00
    };
    private static final int D80_DIRECTORY_TRACK = 39;
    private static final int D80_NUM_SECTORS_IN_DIR_TRACK = 29;
    private static final int D80_SECTOR_SIZE = 256;
    private static final int D80_DIR_ENTRIES_PER_SECTOR = 8;
    private static final int D80_DIR_ENTRY_SIZE = 32;

    private static final String[] D80_FILETYPES = {"DEL", "SEQ", "PRG", "USR", "REL"};
    //private static final int D80_FILETYPE_DEL = 0;
    //private static final int D80_FILETYPE_SEQ = 1;
    //private static final int D80_FILETYPE_PRG = 2;
    //private static final int D80_FILETYPE_USR = 3;
    //private static final int D80_FILETYPE_REL = 4;

    private ByteProvider d80ImageProvider;

    /**
     * File system constructor.
     * 
     * @param fsFSRL The root {@link FSRL} of the file system.
     * @param provider The file system provider.
     */
    public CommodoreD80FileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
        super(fsFSRL, FileSystemService.getInstance());
        this.d80ImageProvider = provider;
    }

    /**
     * Mounts (opens) the file system.
     * 
     * @param monitor A cancellable task monitor.
     * @throws IOException 
     */
    public void mount(TaskMonitor monitor) throws IOException {
        monitor.setMessage("Opening " + CommodoreD80FileSystem.class.getSimpleName() + "...");

        BinaryReader reader = new BinaryReader(d80ImageProvider, true);

        int fsi = 0; // file system index for Ghidra fsIndex.storeFile

        // the directory is on track 39
        long directoryOffset = D80_TRACK_OFFSETS[D80_DIRECTORY_TRACK - 1];
        // sectors are 256 bytes long
        // track 39 has 29 sectors, 0 to 28
        // each sector can contain 8 32-byte entries
        // sector 0 is the header
        // iterate through the other sectors
        for (int s = 1; s < D80_NUM_SECTORS_IN_DIR_TRACK; s++) {
            // iterate through the entries in the sector
            for (int e = 0; e < D80_DIR_ENTRIES_PER_SECTOR; e++) {
                long entryOffset = directoryOffset + (s * D80_SECTOR_SIZE) + (e * D80_DIR_ENTRY_SIZE);

                reader.setPointerIndex(entryOffset);
                final int nextDirTrack = reader.readNextUnsignedByte();
                final int nextDirSector = reader.readNextUnsignedByte();
                final int fileTypeByte = reader.readNextUnsignedByte();
                final int firstFileTrack = reader.readNextUnsignedByte();
                final int firstFileSector = reader.readNextUnsignedByte();
                byte[] filenameBytes = reader.readNextByteArray(16);
                reader.readNextUnsignedShort(); // firstRelSideSectorBlockTrackSector
                reader.readNextUnsignedByte(); // relFileRecordLength
                reader.readNextByteArray(6);
                final int fileSizeInSectors = reader.readNextUnsignedShort();

                String originalFilename = trimA0s(filenameBytes);

                // unused entry?
                if (firstFileTrack == 0 && firstFileSector == 0) {
                    continue;
                }

                final int fileTypeFlags = fileTypeByte & 0xf0;
                final int fileType = fileTypeByte & 0x0F;
                String fileTypeString = "";

                if ((fileTypeFlags & 0x70) != 0 || fileType > 4) {
                    fileTypeString = String.format("0x%02x", fileTypeByte);
                } else {
                    fileTypeString = D80_FILETYPES[fileType];
                    if (fileTypeFlags == 0x80) fileTypeString += "|closed";
                }

                final long diskImageOffsetOfFile = D80_TRACK_OFFSETS[firstFileTrack - 1] + D80_SECTOR_SIZE * firstFileSector;

                String cleanFilename = sanitizeFilename(originalFilename);

                Msg.info(this, String.format("0x%x: 39/%d [%d] (%s) %s 0x%x (%d)",
                    entryOffset, s, e,
                    fileTypeString,
                    originalFilename.equals(cleanFilename)
                        ? String.format("'%s'", originalFilename)
                        : String.format("'%s' <%s>", originalFilename, cleanFilename),
                    diskImageOffsetOfFile,
                    fileSizeInSectors
                ));

                //String str = "";
                int track = firstFileTrack;
                int sector = firstFileSector;
                int size = 0;

                //str += String.format("%d/%d", track, sector);
                while (true) {
                    long offset = D80_TRACK_OFFSETS[track - 1] + D80_SECTOR_SIZE * sector;
                    track = reader.readUnsignedByte(offset);
                    sector = reader.readUnsignedByte(offset + 1);
                    //str += String.format(", %d/%d", track, sector);
                    if (track == 0) {
                        size += sector; // in this case the sector field holds the remaining size
                        break;
                    }
                    size += D80_SECTOR_SIZE - 2;
                }
                //Msg.info(this, str);

                fsIndex.storeFile(
                    //cleanFilename,    // filename
                    cleanFilename + " (" + D80_FILETYPES[fileTypeByte & 0x0F] + ")",
                    fsi++,                // unique index
                    false,              // PET disks don't have directories (other D80s might?)
                    size,                // length
                    new D80Entry(
                        originalFilename,
                        size,
                        fileTypeByte,
                        firstFileTrack,
                        firstFileSector,
                        diskImageOffsetOfFile
                    )
                );
            }
        }
    }

    private String trimA0s(byte[] raw) {
        for (int i = 0; i < raw.length; i++) {
            if ((raw[i] & 0xff) == 0xa0) return new String(raw, 0, i);
        }
        return new String(raw);
    }

    // replace characters allowed in PET filenames but not in modern OS filenames, such as ":"
    private String sanitizeFilename(String filename) {
        return filename.replace(":", "_");
    }

    @Override
    public void close() throws IOException {
        refManager.onClose();
        fsIndex.clear();
        if (d80ImageProvider != null) {
            d80ImageProvider.close();
            d80ImageProvider = null;
        }
    }

    @Override
    public boolean isClosed() {
        return d80ImageProvider == null;
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
            throws IOException, CancelledException {

        RangeMappedByteProvider petFileProvider = new RangeMappedByteProvider(d80ImageProvider, file.getFSRL());

        D80Entry metadata = fsIndex.getMetadata(file);
        long offset = metadata.offset;

        while (true) {
            int t = d80ImageProvider.readByte(offset) & 0xff;
            int s = d80ImageProvider.readByte(offset + 1) & 0xff;

            if (t == 0) {
                // last sector of file, s has special meaning, number of bytes remaining
                petFileProvider.addRange(offset + 2, s);
                return petFileProvider;
            }
            petFileProvider.addRange(offset + 2, D80_SECTOR_SIZE - 2);
            offset = D80_TRACK_OFFSETS[t - 1] + D80_SECTOR_SIZE * s;
        }
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        D80Entry metadata = fsIndex.getMetadata(file);
        FileAttributes att = new FileAttributes();
        if (metadata != null) {
            att.add(FileAttributeType.NAME_ATTR, metadata.name);
            att.add(FileAttributeType.SIZE_ATTR, metadata.size);

            att.add("Filetype", ((metadata.filetype & 0x70) != 0 || (metadata.filetype & 0x0F) > 4)
                ? String.format("0x%02x", metadata.filetype)
                : D80_FILETYPES[metadata.filetype & 0x0F]
            );

            // TODO PR 7062 not yet available as of Ghidra 11.2.1
            // att.add(FileAttributeType.FILENAME_EXT_OVERRIDE, "exe");
        }
        return att;
    }

}
