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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.IntStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
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
	int auxType;
	// disk image / filesystem attributes
	String fileSystem;
	boolean isProDosOrder;

	ProDosEntry(String name, long size,
			int entryBlock, int entryNumber,
			int storageType, int fileType, int keyPointer, int blocksUsed, int auxType,
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
		this.auxType = auxType;
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
    public static final int TRACKS = 35;
    public static final int SECTORS_PER_TRACK = 16;
    public static final int BLOCKS_PER_TRACK = SECTORS_PER_TRACK / 2;
    public static final int SECTOR_SIZE = 256;
    public static final int BLOCK_SIZE = SECTOR_SIZE * 2;
    public static final int DISK_IMAGE_SIZE = TRACKS * SECTORS_PER_TRACK * SECTOR_SIZE;
	public static final int VOLUME_DIRECTORY_START_BLOCK = 2;
	public static final int ENTRY_SIZE = 39;
	public static final int NUM_ENTRIES_PER_BLOCK = (BLOCK_SIZE - 2 * 2) / ENTRY_SIZE; // 2 u16 fields are prev/next block links
	public static final int ST_INACTIVE = 0x0; // deleted
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
	public static final int[] skipTypes = new int[] {
		ST_INACTIVE,
		ST_VOLUME_DIRECTORY_HEADER,
		ST_SUBDIRECTORY_HEADER
	};
	public static final int MAX_BLOCKS_PER_SAPLING_KEY = 256;
	public static final int MAX_BLOCKS_PER_TREE_KEY = 128;
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
			int auxType = blockReader.readUnsignedShort(offset + 0x1f);

			String[] newPath = Arrays.copyOf(currentPath, currentPath.length + 1);
			newPath[currentPath.length] = name;

			long size = -1; // documented size for directories or when otherwise unknown
			if (storageType == ST_SEEDLING) {
				size = BLOCK_SIZE;
			} else if (storageType == ST_SAPLING) {
				size = 0;
				imageReader.setPointerIndex(blockNumberToOffset(keyPointer));
				for (int i = 0; i < MAX_BLOCKS_PER_SAPLING_KEY; i++) {
					int b = imageReader.readNextUnsignedByte();
					if (b == 0) break;
					size += BLOCK_SIZE;
				}
			} else if (storageType == ST_TREE) {
				size = -1; // TODO
			} else if (storageType == ST_SUBDIRECTORY) {
				size = -1;
			} else {
				throw new IOException("Unexpected storage type: " + storageType);
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
					storageType, fileType, keyPointer, blocksUsed, auxType,
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

			long[] offsets = blockNumberToOffsets(metadata.keyPointer);
			seedling.addRange(offsets[0], SECTOR_SIZE);
			seedling.addRange(offsets[1], SECTOR_SIZE);
			return seedling;
		} else if (metadata.storageType == ST_SAPLING) {
			RangeMappedByteProvider sapling = new RangeMappedByteProvider(provider, file.getFSRL());
			long offset = blockNumberToOffset(metadata.keyPointer);
			for (int i = 0; i < MAX_BLOCKS_PER_SAPLING_KEY; i++) {
				int b = provider.readByte(offset + i) & 0xff;
				if (b == 0) break;
				long[] offsets = blockNumberToOffsets(b);
				sapling.addRange(offsets[0], SECTOR_SIZE);
				sapling.addRange(offsets[1], SECTOR_SIZE);
			}
			return sapling;
		} else if (metadata.storageType == ST_TREE) {
			// TODO each byte of the first half-sector (so only 128 entries) is a pointer to a sapling as above
			throw new IOException("ST_TREE not yet implemented");
		} else {
			// something must've gone wrong
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
			// file attributes
			result.add("Entry Block/Number", metadata.entryBlock + "/" + metadata.entryNumber);
			result.add("Storage Type", typeToString(STORAGE_TYPES, metadata.storageType));
			result.add("File Type", typeToString(FILE_TYPES, metadata.fileType));
			result.add("Key Pointer", metadata.keyPointer);
			result.add("Blocks Used", metadata.blocksUsed);
			result.add("Aux Type", String.format("0x%04x", metadata.auxType));
			// disk image / filesystem attributes
			result.add("Filesystem", metadata.fileSystem);
			result.add("Ordering", metadata.isProDosOrder ? "ProDOS" : "DOS 3");
		}
		return result;
	}

	private String typeToString(Map<Integer, String> map, int type) {
		String result = String.format("0x%02x", type);
		if (map.containsKey(type)) result += " (" + map.get(type) + ")";
		return result;
	}

}
