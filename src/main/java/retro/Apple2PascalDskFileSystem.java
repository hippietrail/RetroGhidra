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
    int blockNumStart;
    int blockNumPastEnd;
    int fileType;
    int lastBlockByteCount;
    int modDate;

    PascalEntry(String name, long size,
            int blockNumStart,
            int blockNumPastEnd,
            int fileType,
            int lastBlockByteCount,
            int modDate) {
        this.name = name;
        this.size = size;
        this.blockNumStart = blockNumStart;
        this.blockNumPastEnd = blockNumPastEnd;
        this.fileType = fileType;
        this.lastBlockByteCount = lastBlockByteCount;
        this.modDate = modDate;
    }
}

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = "apple2pascal", // ([a-z0-9]+ only)
		description = "Apple II Pascal", factory = Apple2PascalDskFileSystemFactory.class)
public class Apple2PascalDskFileSystem extends AbstractFileSystem<PascalEntry> {

    public static final int SECTORS_PER_TRACK = 16;
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

        // the pascal fs is like prodos in that a block is two sectors
        // and uses the same sector ordering: 0 = 0, 1 = 15, n = 15 - n
        RangeMappedByteProvider rmbp = new RangeMappedByteProvider(provider, getFSRL());

        for (int s = 11; s >= 4; s--) rmbp.addRange(s * SECTOR_SIZE, SECTOR_SIZE);

        reader = new BinaryReader(rmbp, true);

        int numberOfFilesInDirectory = 0;

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

                // Msg.info(this, "Pascal volume name: '" + new String(volumeName) + "'");
            } else {
                if (e > numberOfFilesInDirectory) break;

                int fileStartBlockNum = reader.readNextUnsignedShort();
                int firstBlockPastEndOfFile = reader.readNextUnsignedShort();
                int fileTypeEtc = reader.readNextUnsignedShort();
                int fileType = fileTypeEtc & 0x0f;

                // read a pascal string
                int fileNameLen = reader.readNextUnsignedByte();
                byte[] fileNameBytes = reader.readNextByteArray(fileNameLen);
                // file name is 1 to 15 chars long, to skip over the rest we have to read
                if (fileNameLen < 15) reader.readNextByteArray(15 - fileNameLen);

                int numberOfBytesUsedInLastBlock = reader.readNextUnsignedShort();
                int modificationDate = reader.readNextUnsignedShort();

                // Msg.info(this, "Pascal file name: " + e + ": '" + new String(fileNameBytes) + "'");

                int size = (firstBlockPastEndOfFile - fileStartBlockNum) * SECTOR_SIZE * 2;

                String name = new String(fileNameBytes);

                fsIndex.storeFile(
                    name, e, false, size,
                    new PascalEntry(
                        // standard attributes
                        name, size,
                        // file attributes
                        fileStartBlockNum,
                        firstBlockPastEndOfFile,
                        fileType,
                        numberOfBytesUsedInLastBlock,
                        modificationDate
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
        if (metadata == null) return null;

        RangeMappedByteProvider rmbp = new RangeMappedByteProvider(provider, file.getFSRL());

        for (int b = metadata.blockNumStart; b < metadata.blockNumPastEnd; b++) {
            int s1 = b * 2;
            int s2 = b * 2 + 1;
            int t1 = s1 >> 4;
            int t2 = s2 >> 4;
            s1 = s1 & 0x0f;
            s2 = s2 & 0x0f;

            // if sector ordering is not ProDOS, convert logical sector num to image sector num
            if (s1 != 0 && s1 != 15) s1 = 15 - s1;
            if (s2 != 0 && s2 != 15) s2 = 15 - s2;

            long o1 = t1 * SECTORS_PER_TRACK * SECTOR_SIZE + s1 * SECTOR_SIZE;
            long o2 = t2 * SECTORS_PER_TRACK * SECTOR_SIZE + s2 * SECTOR_SIZE;

            rmbp.addRange(o1, SECTOR_SIZE);
            rmbp.addRange(o2, SECTOR_SIZE);
        }

        return rmbp;
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
            result.add("Last Block Byte Count", metadata.lastBlockByteCount);
            int y = metadata.modDate >> 9;
            result.add("Date Modified", (y < 40 ? 2000 + y : 1900 + y) + "-" + ((metadata.modDate >> 4) & 0x1f) + "-" + (metadata.modDate & 0x0f));
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
