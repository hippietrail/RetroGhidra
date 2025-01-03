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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.IntStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
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
	int storageType;
	int entryBlock;
	int entryNumber;
	// disk image / filesystem attributes
	String fileSystem;
	boolean isProDosOrder;
	// a map of named attributes using String keys
	Map<String, String> map;
	// temporary, might or might not be used
	long offset;

	ProDosEntry(String name, long size,
			int storageType,
			int entryBlock, int entryNumber,
			String fileSystem, boolean isProDosOrder,
			Map<String, String> map,
			long offset) {
		// standard attributes
		this.name = name;
		this.size = size;
		// file attributes
		this.storageType = storageType;
		this.entryBlock = entryBlock;
		this.entryNumber = entryNumber;
		// disk image / filesystem attributes
		this.fileSystem = fileSystem;
		this.isProDosOrder = isProDosOrder;
		this.map = map;
		// temporary, might or might not be used
		this.offset = 0;
	}
}

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = "prodos", // ([a-z0-9]+ only)
		description = "Apple II ProDOS", factory = Apple2ProDosDskFileSystemFactory.class)
public class Apple2ProDosDskFileSystem extends AbstractFileSystem<ProDosEntry> {

	// http://www.easy68k.com/paulrsm/6502/PDOS8TRM.HTM
	// https://ciderpress2.com/formatdoc/ProDOS-notes.html
    public static final int TRACKS = 35;
    public static final int SECTORS_PER_TRACK = 16;
    public static final int BLOCKS_PER_TRACK = SECTORS_PER_TRACK / 2;
    public static final int SECTOR_SIZE = 256;
    public static final int BLOCK_SIZE = SECTOR_SIZE * 2;
    public static final int DISK_IMAGE_SIZE = TRACKS * SECTORS_PER_TRACK * SECTOR_SIZE;
	public static final int ST_INACTIVE = 0x0;
	public static final int ST_SEEDLING = 0x1;
	public static final int ST_SAPLING = 0x2;
	public static final int ST_TREE = 0x3;
	public static final int ST_PASCAL = 0x4;
	public static final int ST_SUBDIRECTORY = 0xD;
	public static final int ST_SUBDIRECTORY_HEADER = 0xE;
	public static final int ST_VOLUME_DIRECTORY_HEADER = 0xF;
	public static final Map<Integer, String> STORAGE_TYPES = Map.of(
		ST_INACTIVE, "inactive file entry",
		ST_SEEDLING, "seedling file entry",
		ST_SAPLING, "sapling file entry",
		ST_TREE, "tree file entry",
		ST_PASCAL, "Pascal area",
		ST_SUBDIRECTORY, "subdirectory file entry",
		ST_SUBDIRECTORY_HEADER, "subdirectory header",
		ST_VOLUME_DIRECTORY_HEADER, "volume directory header"
	);
	public static final int FT_TYPELESS = 0x00;
	public static final int FT_TEXT = 0x04;
	public static final int FT_BINARY = 0x06;
	public static final int FT_DIRECTORY = 0x0f;
	public static final int FT_INTEGER_BASIC = 0xfa;
	public static final int FT_APPLESOFT_BASIC = 0xfc;
	public static final int FT_RELOCATABLE = 0xfe;
	public static final int FT_SYSTEM = 0xff;
	public static final Map<Integer, String> FILE_TYPES = Map.of(
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

		for (int b = 2; b != 0;) {
			if (monitor.isCancelled())  break;

			BinaryReader blockReader = new BinaryReader(new ByteArrayProvider(getBlock(imageReader, b)), true);

			int nextDirBlock = blockReader.readNextUnsignedShort();
			int prevDirBlock = blockReader.readNextUnsignedShort();

			// the rest of the block is a series of 39-byte directory entries
			int i = 0;
			for (int o = 4; o < BLOCK_SIZE - 39; o += 39) {
				blockReader.setPointerIndex(o);
				int storageTypeAndNameLength = blockReader.readNextUnsignedByte();
				int storageType = storageTypeAndNameLength >> 4;

				if (storageType == 0) continue;

				int nameLength = storageTypeAndNameLength & 0x0f;
				String name = new String(blockReader.readNextByteArray(nameLength));
				if (nameLength != 15) blockReader.readNextByteArray(15 - nameLength);

				// TODO read the other fields... but those depend on the storage type!

				switch (storageType) {
					case 0xf:
						handleVolumeDirectoryHeader(blockReader, b, i, name);
						break;
					/*case 0xe:
						storeSubdirectoryHeader(blockReader, b, i, name);
						break;*/
					default:
						handleFileEntry(blockReader, b, i, storageType, name);
				}
				i++;
			}
			b = nextDirBlock;
		}
	}

	// the block reader is positioned at the start of the VDH
	// this is not really a dirent but we're treating it as one for now so we can examine its attributes
	// might make more sense as separate handle and store methods
	private void handleVolumeDirectoryHeader(BinaryReader blockReader, int entryBlock, int entryNumber, String name) throws IOException {
        blockReader.readNextByteArray(8);
		byte[] creationDateAndTime = blockReader.readNextByteArray(4);
		int version = blockReader.readNextUnsignedByte();
		int minVersion = blockReader.readNextUnsignedByte();
		int access = blockReader.readNextUnsignedByte();
		int entryLength = blockReader.readNextUnsignedByte();
		int entriesPerBlock = blockReader.readNextUnsignedByte();
		int fileCount = blockReader.readNextUnsignedShort();
		/*int bitMapPointer = */blockReader.readNextUnsignedShort();
		int totalBlocks = blockReader.readNextUnsignedShort();

		boolean blankCreation = creationDateAndTime[0] == 0 && creationDateAndTime[1] == 0 && creationDateAndTime[2] == 0 && creationDateAndTime[3] == 0;

		int size = 16; // random for now

		// Msg.info(this, "VDH '" + name);

		Map<String, String> map = new LinkedHashMap<>();
		map.put("Kind", "Volume Directory Header");
		if (!blankCreation) {
			map.put("Creation Date", dateBytesToString(creationDateAndTime));
			map.put("Creation Time", timeBytesToString(creationDateAndTime));
		}
		map.put("Version", String.valueOf(version));
		map.put("Min Version", String.valueOf(minVersion));
		map.put("Access", String.format("0x%02x", access));
		map.put("Entry Length", String.valueOf(entryLength));
		map.put("Entries Per Block", String.valueOf(entriesPerBlock));
		map.put("File Count", String.valueOf(fileCount));
		map.put("Total Blocks", String.valueOf(totalBlocks));

		fsIndex.storeFile(
			name,
			entryNumber,
			false, // TODO ProDOS *does* have directories!
			size,
			new ProDosEntry(
				// standard attributes
				name, size,
				// file attributes
				0xf,
				entryBlock, entryNumber,
				// disk image / filesystem attributes
				"ProDOS", isProDosOrder,
				map,
				// temporary, might or might not be used
				0 // TODO 'o' is the offset into the block, which is made of 2 sectors, not necessarily contiguous
			)
		);
	}

	/*private void storeSubdirectoryHeader(BinaryReader blockReader, int entryBlock, int entryNumber, String name) throws IOException {
		blockReader.readNextByteArray(8);

		int size = 16; // random for now

		// Msg.info(this, "Subdir '" + name);

		Map<String, String> map = new LinkedHashMap<>();
		map.put("Kind", "Subdir");

		fsIndex.storeFile(
			name,
			entryNumber,
			false, // TODO ProDOS *does* have directories!
			size,
			new ProDosEntry(
				// standard attributes
				name, size,
				// file attributes
				0xe,
				entryBlock, entryNumber,
				// disk image / filesystem attributes
				"ProDOS", isProDosOrder,
				map,
				// temporary, might or might not be used
				0 // TODO 'o' is the offset into the block, which is made of 2 sectors, not necessarily contiguous
			)
		);
	}*/

	// the block reader is positioned at the start of the file entry
	// an entry may be a file or a directory, the latter of which is not handled yet
	private void handleFileEntry(BinaryReader blockReader, int entryBlock, int entryNumber, int storageType, String name) throws IOException {
		int fileType = blockReader.readNextUnsignedByte();
		int keyPointer = blockReader.readNextUnsignedShort();
		int blocksUsed = blockReader.readNextUnsignedShort();
		long eof = blockReader.readNextUnsignedValue(3);
		byte[] creationDateAndTime = blockReader.readNextByteArray(4);
		int version = blockReader.readNextUnsignedByte();
		int minVersion = blockReader.readNextUnsignedByte();
		int access = blockReader.readNextUnsignedByte();
		int auxType = blockReader.readNextUnsignedShort();
		byte[] lastMod = blockReader.readNextByteArray(4);
		int headerPointer = blockReader.readNextUnsignedShort();

		long[] offs = blockNumberToOffsets(keyPointer);
	    Msg.info(this, "Block offsets for '" + name + "': " + Arrays.toString(Arrays.stream(offs).mapToObj(o -> String.format("0x%x", o)).toArray(String[]::new)));

		boolean blankCreation = creationDateAndTime[0] == 0 && creationDateAndTime[1] == 0 && creationDateAndTime[2] == 0 && creationDateAndTime[3] == 0;
		boolean blankLastMod = lastMod[0] == 0 && lastMod[1] == 0 && lastMod[2] == 0 && lastMod[3] == 0;

		int size = 16; // random for now

		// Msg.info(this, "File '" + name);

		Map<String, String> map = new LinkedHashMap<>();
		map.put("Kind", "File");
		map.put("File Type", filetypeToString(fileType));
		map.put("Blocks Used", String.valueOf(blocksUsed));
		map.put("EOF", Long.toString(eof));
		if (!blankCreation) {
			map.put("Creation Date", dateBytesToString(creationDateAndTime));
			map.put("Creation Time", timeBytesToString(creationDateAndTime));
		}
		map.put("Version", String.valueOf(version));
		map.put("Min Version", String.valueOf(minVersion));
		map.put("Access", String.format("0x%02x", access));
		map.put("Aux Type", String.format("0x%04x", auxType));
		if (!blankLastMod) {
			map.put("Last Mod Date", dateBytesToString(lastMod));
			map.put("Last Mod Time", timeBytesToString(lastMod));
		}
		// map.put("Header Pointer", String.format("0x%04x", headerPointer));

		fsIndex.storeFile(
			name,
			entryNumber,
			storageType == 0xd,
			size,
			new ProDosEntry(
				// standard attributes
				name, size,
				// file attributes
				storageType,
				entryBlock, entryNumber,
				// disk image / filesystem attributes
				"ProDOS", isProDosOrder,
				map,
				// temporary, might or might not be used
				0 // TODO 'o' is the offset into the block, which is made of 2 sectors, not necessarily contiguous
			)
		);
	}

	private String filetypeToString(int fileType) {
		String result = String.format("0x%02x", fileType);
		if (FILE_TYPES.containsKey(fileType)) {
			result += " (" + FILE_TYPES.get(fileType) + ")";
		}
		return result;
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
		int[] trackAndSector = getTrackAndSector(blockNum);
		return logicalTrackAndSectorToOffset(trackAndSector[0], trackAndSector[1]);
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
		return (metadata != null)
				// TODO
				? new ByteProviderWrapper(provider, metadata.offset, metadata.size, file.getFSRL())
				: null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		ProDosEntry metadata = fsIndex.getMetadata(file);
		FileAttributes result = new FileAttributes();
		if (metadata != null) {
			// standard attributes
			result.add(FileAttributeType.NAME_ATTR, metadata.name);
			result.add(FileAttributeType.SIZE_ATTR, metadata.size);
			// file attributes
			result.add("Storage Type", storageTypeToString(metadata.storageType)); //String.format("0x%1x", metadata.storageType));
			result.add("Entry Block/Number", metadata.entryBlock + "/" + metadata.entryNumber);
			// disk image / filesystem attributes
			result.add("Filesystem", metadata.fileSystem);
			result.add("Ordering", metadata.isProDosOrder ? "ProDOS" : "DOS 3");

			// VDH, dubdir, and file each have a different set of attributes
			for (Map.Entry<String, String> entry : metadata.map.entrySet()) {
				result.add(entry.getKey(), entry.getValue());
			}

			// ignoring offset for now
		}
		return result;
	}

	private String storageTypeToString(int fileType) {
		String result = String.format("0x%02x", fileType);
		if (STORAGE_TYPES.containsKey(fileType)) {
			result += " (" + STORAGE_TYPES.get(fileType) + ")";
		}
		return result;
	}

}
