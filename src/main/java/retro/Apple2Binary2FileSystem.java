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
import java.util.Date;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class BnyEntry {
    // standard attributes
    String name;
    long offset;
    long size;
    int modDate;
    int modTime;
    int createDate;
    int createTime;
    // file attributes
    int filetypeCode;
    int auxTypeCode;
    // more file attributes
    int osType;

    BnyEntry(String name, long offset, long size,
            int modDate, int modTime, int createDate, int createTime,
            int filetypeCode, int auxTypeCode,
            int osType) {
        this.name = name;
        this.offset = offset;
        this.size = size;
        this.modDate = modDate;
        this.modTime = modTime;
        this.createDate = createDate;
        this.createTime = createTime;
        this.filetypeCode = filetypeCode;
        this.auxTypeCode = auxTypeCode;

        this.osType = osType;
    }
}

/**
 * A {@link GFileSystem} implementation for Apple II Binary II.
 * 
 * @see <a href="https://wiki.preterhuman.net/Apple_II_Binary_File_Format">Apple II Binary File Format</a>
 */
@FileSystemInfo(type = Apple2Binary2FileSystem.FS_TYPE, description = "Apple II Binary II",
        factory = Apple2Binary2FileSystemFactory.class)
public class Apple2Binary2FileSystem extends AbstractFileSystem<BnyEntry> {

    public static final String FS_TYPE = "bny"; // ([a-z0-9]+ only)

    // Offset  Length                  Contents
    // ------  ------   ---------------------------------------
    // +0       3      ID bytes: always $0A $47 $4C
    // +3       1      access code
    // +4       1      file type code
    // +5       2      auxiliary type code
    // +7       1      storage type code
    // +8       2      size of file in 512-byte blocks
    // +10      2      date of modification
    // +12      2      time of modification
    // +14      2      date of creation
    // +16      2      time of creation
    // +18      1      ID byte: always $02
    // +19      1      [reserved]
    // +20      3      end-of-file (EOF) position
    // +23      1      length of filename/partial pathname
    // +24      64     ASCII filename or partial pathname
    // +88      23     [reserved, must be zero]
    // +111     1      ProDOS 16 access code (high)
    // +112     1      ProDOS 16 file type code (high)
    // +113     1      ProDOS 16 storage type code (high)
    // +114     2      ProDOS 16 size of file in blocks (high)
    // +116     1      ProDOS 16 end-of-file position (high)
    // +117     4      disk space needed
    // +121     1      operating system type
    // +122     2      native file type code
    // +124     1      phantom file flag
    // +125     1      data flags
    // +126     1      Binary II version number
    // +127     1      number of files to follow

    // ID, access code
    private static final int BNY_OFF_FILETYPE_CODE = 4;
    private static final int BNY_OFF_AUX_TYPE_CODE = 5; // 16-bit
    // storage type code, size in blocks, (id), (reserved)
    private static final int BNY_OFF_MOD_DATE = 10;
    private static final int BNY_OFF_MOD_TIME = 12;
    private static final int BNY_OFF_CREATE_DATE = 14;
    private static final int BNY_OFF_CREATE_TIME = 16;
    private static final int BNY_OFF_EOF_POSITION = 20; // 24-bit
    private static final int BNY_OFF_FILENAME_LEN = 23; // (or partial pathname)
    private static final int BNY_OFF_FILENAME = 24; // 64 bytes (or partial pathname)
    // reserved
    // prodos 16: access code hi, filetype code hi, storage type code hi, size in blocks hi, eof position hi
    // disk space needed, os type, , native file type code, phantom file flag, data flags, binary ii version, num files to follow
    private static final int BNY_OFF_OS_TYPE = 121;
    private static final int BNY_HEADER_LEN = 128;

    private static final int BNY_MAX_FILENAME_LEN = 64;

    private static final int OS_PRODOS = 0;
    private static final int OS_DOS3 = 1;
    private static final int OS_PASCAL = 2;
    private static final int OS_CPM = 3;
    private static final int OS_MS_DOS = 4;
    private static final Map<Integer, String> OS_TYPES = Map.of(
        OS_PRODOS, "ProDOS",
        OS_DOS3, "DOS 3",
        OS_PASCAL, "Pascal",
        OS_CPM, "CP/M",
        OS_MS_DOS, "MS-DOS"
    );

    private ByteProvider provider;

    /**
     * File system constructor.
     * 
     * @param fsFSRL The root {@link FSRL} of the file system.
     * @param provider The file system provider.
     */
    public Apple2Binary2FileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
        super(fsFSRL, FileSystemService.getInstance());
        this.provider = provider;
    }

    /**
     * Mounts (opens) the file system.
     * 
     * @param monitor A cancellable task monitor.
     * @throws IOException 
     */
    public void mount(TaskMonitor monitor) throws IOException {
        monitor.setMessage("Opening " + Apple2Binary2FileSystem.class.getSimpleName() + "...");

        BinaryReader reader = new BinaryReader(provider, true);
        long off = 0;
        int i = 0;
        while (off < reader.length() && monitor.isCancelled() == false) {
            final int filetypeCode = reader.readUnsignedByte(off + BNY_OFF_FILETYPE_CODE);
            final int auxTypeCode = reader.readUnsignedShort(off + BNY_OFF_AUX_TYPE_CODE);
            final int modDate = reader.readUnsignedShort(off + BNY_OFF_MOD_DATE);
            final int modTime = reader.readUnsignedShort(off + BNY_OFF_MOD_TIME);
            final int createDate = reader.readUnsignedShort(off + BNY_OFF_CREATE_DATE);
            final int createTime = reader.readUnsignedShort(off + BNY_OFF_CREATE_TIME);
            // 'end of file position' is what it's called in the documentation, but it is the file length
            // this can seem confusing today but in that era files were often measured in sectors or blocks
            final long eofPos = reader.readUnsignedValue(off + BNY_OFF_EOF_POSITION, 3);

            final int filenameLen = reader.readUnsignedByte(off + BNY_OFF_FILENAME_LEN);
            final String filename = reader.readAsciiString(off + BNY_OFF_FILENAME, filenameLen);

            final int osType = reader.readUnsignedByte(off + BNY_OFF_OS_TYPE);

            long dataBlocks = eofPos / 128;
            if (eofPos % 128 != 0) dataBlocks++;
            long endOffset = off + BNY_HEADER_LEN + dataBlocks * 128;

            // TODO would be nice to have an option to include the headers or not
            // NOTE that in BNY the magic word exists in every entry
            // NOTE there are only entry headers, there is no overall header
            // NOTE so an archive is simply a concatenation of files with entry headers
            // String filetype = (filetypeCode == 4) ? "text" : (filetypeCode == 6) ? "binary" : "0x" + Integer.toHexString(filetypeCode);
            // Msg.info(this, i + ": " + filename + " ; type:" + filetype + " ; offset:0x" + Long.toHexString(off) + " ; aux:0x" + Integer.toHexString(auxTypeCode));

            fsIndex.storeFile(
                filename,                   // path
                i++,                        // file index
                false,                      // is directory
                eofPos,                     // length

                new BnyEntry(
                    filename,               // name
                    off + BNY_HEADER_LEN,   // offset
                    eofPos,                 // name is confusing, it's just the size

                    modDate,
                    modTime,
                    createDate,
                    createTime,

                    filetypeCode,           // filetype code
                    auxTypeCode,            // aux type code

                    osType
                )
            );

            off = endOffset;
            // i++;
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

        BnyEntry metadata = fsIndex.getMetadata(file);
        return (metadata != null)
                ? new ByteProviderWrapper(provider, metadata.offset, metadata.size, file.getFSRL())
                : null;
    }

    public BnyEntry getMetadata(GFile file) {
        return fsIndex.getMetadata(file);
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        BnyEntry metadata = fsIndex.getMetadata(file);
        FileAttributes result = new FileAttributes();
        if (metadata != null) {
            result.add(FileAttributeType.NAME_ATTR, metadata.name);
            result.add(FileAttributeType.SIZE_ATTR, metadata.size);
            int y = metadata.modDate >> 9;
            y = y < 40 ? 2000 + y : 1900 + y;
            int mon = (metadata.modDate >> 5) & 0x0f;
            int d = metadata.modDate & 0x1f;
            int h = metadata.modTime >> 8;
            int min = metadata.modTime & 0x3f;
            result.add(FileAttributeType.MODIFIED_DATE_ATTR, new Date(y - 1900, mon, d, h, min));
            y = metadata.createDate >> 9;
            y = y < 40 ? 2000 + y : 1900 + y;
            mon = (metadata.createDate >> 5) & 0x0f;
            d = metadata.createDate & 0x1f;
            h = metadata.createTime >> 8;
            min = metadata.createTime & 0x3f;
            result.add(FileAttributeType.CREATE_DATE_ATTR, new Date(y - 1900, mon, d, h, min));
            String filetypeString = filetypeToString(metadata.filetypeCode);
            String auxTypeString = (metadata.filetypeCode == 6) ? String.format("0x%04x", metadata.auxTypeCode) : Integer.toString(metadata.auxTypeCode);
            result.add("Filetype", filetypeString);
            result.add("OS Type", osTypeToString(metadata.osType));
        }
        return result;
    }

    public static String filetypeToString(int filetypeCode) {
        String result = String.format("0x%02x", filetypeCode);
        if (filetypeCode == 4) result = "text";
        else if (filetypeCode == 6) result = "binary";
        return result;
    }

    public static String osTypeToString(int osType) {
        String result = String.format("0x%02x", osType);
        if (OS_TYPES.containsKey(osType)) result = OS_TYPES.get(osType);
        return result;
    }

}
