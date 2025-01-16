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
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class HqxEntry {
    // standard attributes
    String name;
    long size;

    HqxEntry(String name, long size) {
        this.name = name;
        this.size = size;
    }
}

/**
 * A {@link GFileSystem} implementation of BinHex 4.0 (.hqx).
 */
@FileSystemInfo(type = BinHex4FileSystem.FS_TYPE, description = "BinHex 4.0",
        factory = BinHex4FileSystemFactory.class)
public class BinHex4FileSystem extends AbstractFileSystem<HqxEntry> {

    public static final String FS_TYPE = "hqx"; // ([a-z0-9]+ only)

    private ByteProvider provider;

    /**
     * File system constructor.
     * 
     * @param fsFSRL The root {@link FSRL} of the file system.
     * @param provider The file system provider.
     */
    public BinHex4FileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
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
        monitor.setMessage("Opening " + BinHex4FileSystem.class.getSimpleName() + "...");

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

        HqxEntry metadata = fsIndex.getMetadata(file);

        // TODO

        return null;
    }

    public HqxEntry getMetadata(GFile file) {
        return fsIndex.getMetadata(file);
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        HqxEntry metadata = fsIndex.getMetadata(file);
        FileAttributes result = new FileAttributes();
        if (metadata != null) {
            result.add(FileAttributeType.NAME_ATTR, metadata.name);
        }
        return result;
    }

}