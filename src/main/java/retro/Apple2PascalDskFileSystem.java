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
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.RangeMappedByteProvider;
import ghidra.formats.gfilesystem.AbstractFileSystem;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class PascalEntry {
    // standard attributes
    String name;
    long size;
    // file attributes
    int fileType;
    int modDate;
    // temporary, might or might not be used
    long offset;

    PascalEntry(String name, long size,
            int fileType,
            int modDate,
            long offset) {
        this.name = name;
        this.size = size;
        this.fileType = fileType;
        this.modDate = modDate;
        this.offset = offset;
    }
}

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = "apple2pascal", // ([a-z0-9]+ only)
		description = "Apple II Pascal", factory = Apple2PascalDskFileSystemFactory.class)
public class Apple2PascalDskFileSystem extends AbstractFileSystem<PascalEntry> {

    public static final int SECTOR_SIZE = 256;
    public static final int FT_UNTYPED = 0;
    public static final int FT_XDSK = 1;
    public static final int FT_CODE = 2;
    public static final int FT_TEXT = 3;
    public static final int FT_INFO = 4;
    public static final int FT_DATA = 5;
    public static final int FT_GRAF = 6;
    public static final int FT_FOTO = 7;
    public static final int FT_SECUREDIR = 8;
    public static final Map<Integer, String> FILE_TYPES = Map.of(
        FT_UNTYPED, "UNTYPED",
        FT_XDSK, "XDSK",
        FT_CODE, "CODE",
        FT_TEXT, "TEXT",
        FT_INFO, "INFO",
        FT_DATA, "DATA",
        FT_GRAF, "GRAF",
        FT_FOTO, "FOTO",
        FT_SECUREDIR, "SECUREDIR"
    );

    private ByteProvider provider;

    /**
     * File system constructor.
     *
     * @param fsFSRL The file system root location.
     * @param provider The byte provider for the file system.
     */
    public Apple2PascalDskFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
        super(fsFSRL, FileSystemService.getInstance());
        this.provider = provider;
    }

    /*
     * Mounts (opens) the file system.
     *
     * @param monitor A cancellable task monitor.
     */
    public void mount(TaskMonitor monitor) throws IOException {
        monitor.setMessage("Opening " + Apple2PascalDskFileSystem.class.getSimpleName() + "...");

        BinaryReader reader = new BinaryReader(provider, true);

        // TODO
        // The directory starts in block 2. All disks have a 2048-byte directory spanning blocks 2 through 5 (inclusive)
        // the pascal fs is like prodos in that a block is two sectors
        // and uses the same sector ordering: 0 = 0, 1 = 15, n = 15 - n
        // so lets make a new byteprovider/binaryreader of sectors 4 through 10+11 in reverse order
        // we can use RangeMappedByteProvider to get an in-order version of the catalog/directory
        RangeMappedByteProvider rmbp = new RangeMappedByteProvider(provider, getFSRL());
        // a loop calling `addRange(long offset, long rangeLen`
        for (int s = 11; s >= 4; s--) rmbp.addRange(s * SECTOR_SIZE, SECTOR_SIZE);

        reader = new BinaryReader(rmbp, true);

        int numberOfFilesInDirectory = 0;

        // Each directory entry is 26 bytes long, providing space for 78 entries
        for (int e = 0; e < 78; e++) {
            if (e == 0) {
                int sysAreaStartBlockNum = reader.readNextUnsignedShort();
                int nextBlock = reader.readNextUnsignedShort();
                int fileType = reader.readNextUnsignedShort();
                // read a pascal string
                int volumeNameLen = reader.readNextUnsignedByte();
                byte[] volumeName = reader.readNextByteArray(volumeNameLen);
                // volume name is 1 to 7 chars long, to skip over the rest we have to read
                if (volumeNameLen < 7) reader.readNextByteArray(7 - volumeNameLen);

                int numberOfBlocksInVolume = reader.readNextUnsignedShort();
                numberOfFilesInDirectory = reader.readNextUnsignedShort();
                int lastAccessTime = reader.readNextUnsignedShort(); // always zero
                long mostRecentlySetDateValue = reader.readNextUnsignedShort();
                reader.readNextUnsignedInt(); // reserved

                Msg.info(this, "Pascal volume name: '" + new String(volumeName) + "'");
                // Msg.info(this, "  offset now: 0x" + Long.toHexString(reader.getPointerIndex()));
            } else {
                if (e > numberOfFilesInDirectory) break;

                int fileStartBlockNum = reader.readNextUnsignedShort();
                int firstBlockPastEndOfFile = reader.readNextUnsignedShort();
                int fileTypeEtc = reader.readNextUnsignedShort();
                int fileType = fileTypeEtc & 0x0f;
                // read a pascal string
                int fileNameLen = reader.readNextUnsignedByte();
                //if (fileNameLen == 0) break;

                byte[] fileNameBytes = reader.readNextByteArray(fileNameLen);
                // file name is 1 to 15 chars long, to skip over the rest we have to read
                if (fileNameLen < 15) reader.readNextByteArray(15 - fileNameLen);
                int numberOfBytesUsedInLastBlock = reader.readNextUnsignedShort();
                int modificationDate = reader.readNextUnsignedShort();

                Msg.info(this, "Pascal file name: " + e + ": '" + new String(fileNameBytes) + "'");
                // Msg.info(this, "  offset now: 0x" + Long.toHexString(reader.getPointerIndex()));

                int size = (firstBlockPastEndOfFile - fileStartBlockNum) * SECTOR_SIZE;
                if (size > numberOfBytesUsedInLastBlock) {
                    size = size - SECTOR_SIZE + numberOfBytesUsedInLastBlock;
                }

                String name = new String(fileNameBytes);

                fsIndex.storeFile(
                    // standard attributes
                    name,
                    e,
                    false,
                    size,
                    new PascalEntry(
                        // standard attributes
                        name, size,
                        // file attributes
                        fileType, modificationDate,
                        // TODO
                        0
                    )
                );
            }
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

        PascalEntry metadata = fsIndex.getMetadata(file);
        return (metadata != null)
                // TODO
                ? new ByteProviderWrapper(provider, metadata.offset, metadata.size, file.getFSRL())
                : null;
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        PascalEntry metadata = fsIndex.getMetadata(file);
        FileAttributes result = new FileAttributes();
        if (metadata != null) {
            // standard attributes
            result.add(FileAttributeType.NAME_ATTR, metadata.name);
            result.add(FileAttributeType.SIZE_ATTR, metadata.size);
            // file attributes
            result.add("File Type", filetypeToString(metadata.fileType));
            int y = metadata.modDate >> 9;
            int m = (metadata.modDate >> 4) & 0x1f;
            int d = metadata.modDate & 0x0f;
            result.add("Date Modified", (y < 40 ? 2000 + y : 1900 + y) + "-" + m + "-" + d);
        }
        return result;
    }

	private String filetypeToString(int fileType) {
		String result = String.format("0x%02x", fileType);
		if (FILE_TYPES.containsKey(fileType)) {
			result += " (" + FILE_TYPES.get(fileType) + ")";
		}
		return result;
	}

}
