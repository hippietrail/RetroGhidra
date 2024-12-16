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
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class Dos3Entry {
	String name;
	int size;
	int offset;
}

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = "dos3", // ([a-z0-9]+ only)
		description = "Apple II DOS 3.3", factory = Apple2Dos3DskFileSystemFactory.class)
public class Apple2Dos3DskFileSystem extends AbstractFileSystem<Dos3Entry> {

	// TODO link to references
	// TODO public static final constants

	private ByteProvider provider;

	/**
	 * File system constructor.
	 * 
	 * @param fsFSRL The root {@link FSRL} of the file system.
	 * @param provider The file system provider.
	 */
	public Apple2Dos3DskFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		super(fsFSRL, FileSystemService.getInstance());
		this.provider = provider;
	}

	/**
	 * Mounts (opens) the file system.
	 * 
	 * @param monitor A cancellable task monitor.
	 */
	public void mount(TaskMonitor monitor) {
		monitor.setMessage("Opening " + Apple2Dos3DskFileSystem.class.getSimpleName() + "...");

	    BinaryReader reader = new BinaryReader(provider, true);
		// // TODO: Customize how things in the file system are stored.  The following should be 
		// // treated as pseudo-code.
		// for (MyMetadata metadata : new MyMetadata[10]) {
		// 	if (monitor.isCancelled()) {
		// 		break;
		// 	}
		// 	fsih.storeFile(metadata.path, fsih.getFileCount(), false, metadata.size, metadata);
		// }
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
		return (metadata != null)
				? new ByteProviderWrapper(provider, metadata.offset, metadata.size, file.getFSRL())
				: null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		Dos3Entry metadata = fsIndex.getMetadata(file);
		FileAttributes result = new FileAttributes();
		if (metadata != null) {
			result.add(FileAttributeType.NAME_ATTR, metadata.name);
			result.add(FileAttributeType.SIZE_ATTR, metadata.size);
		}
		return result;
	}

}
