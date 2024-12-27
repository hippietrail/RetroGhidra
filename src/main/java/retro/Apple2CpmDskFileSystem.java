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
import ghidra.formats.gfilesystem.AbstractFileSystem;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class CpmEntry {
    String name;
    long size;
    long offset;

    CpmEntry(String name, long size,
            long offset) {
        this.name = name;
        this.size = size;
        this.offset = offset;
    }
}

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = "apple2cpm", // ([a-z0-9]+ only)
		description = "Apple II CP/M", factory = Apple2CpmDskFileSystemFactory.class)
public class Apple2CpmDskFileSystem extends AbstractFileSystem<CpmEntry> {

    private ByteProvider provider;

    /**
     * File system constructor.
     *
     * @param fsFSRL The file system root location.
     * @param provider The byte provider for the file system.
     */
    public Apple2CpmDskFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
        super(fsFSRL, FileSystemService.getInstance());
        this.provider = provider;
    }

    /*
     * Mounts (opens) the file system.
     *
     * @param monitor A cancellable task monitor.
     */
    public void mount(TaskMonitor monitor) throws IOException {
        monitor.setMessage("Opening " + Apple2CpmDskFileSystem.class.getSimpleName() + "...");

        BinaryReader reader = new BinaryReader(provider, true);

        // TODO
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

        CpmEntry metadata = fsIndex.getMetadata(file);
        return (metadata != null)
                // TODO
                ? new ByteProviderWrapper(provider, metadata.offset, metadata.size, file.getFSRL())
                : null;
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        CpmEntry metadata = fsIndex.getMetadata(file);
        FileAttributes result = new FileAttributes();
        if (metadata != null) {
            // standard attributes
            result.add(FileAttributeType.NAME_ATTR, metadata.name);
            result.add(FileAttributeType.SIZE_ATTR, metadata.size);
            // TODO
        }
        return result;
    }

}
