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
import java.nio.file.FileSystem;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.RefdFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import retro.Apple2Binary2FileSystem;
import retro.Apple2Dos3DskFileSystem;
import retro.Apple2PascalDskFileSystem;
import retro.Apple2ProDosDskFileSystem;
import retro.CommodoreD80FileSystem;

/**
* A {@link Loader} for loading files from RetroGhidra Commodore disk {@link FileSystem}s such as .D80.
*/
public class CommodoreDiskFileLoader extends AbstractProgramWrapperLoader {

    private static final String NAME = "Commodore Disk File";
    // FSRLs call these "protocols" but FileSystems call them "types"
    private static final String[] PROTOCOLS = {
        CommodoreD80FileSystem.FS_TYPE,
    };

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public List<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) {
        List <LoadSpec> loadSpecs = new ArrayList <>();

        String protocol = provider.getFSRL().getFS().getProtocol();

        if (Arrays.asList(PROTOCOLS).contains(protocol)) {
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
            // and for Z80 files on the SuperPET, since I don't think we can test for that
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));
        }

        return loadSpecs;
    }

    @Override
    public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        // get the filetype, length, load address, and entry point
        FileSystemService fsService = FileSystemService.getInstance();

        try {
            RefdFile rf = fsService.getRefdFile(provider.getFSRL(), null);
            GFileSystem cfs = rf.fsRef.getFilesystem();
            GFile f = cfs.lookup(provider.getFSRL().getPath());

            Object metadata = switch (cfs) {
                case CommodoreD80FileSystem fs -> fs.getMetadata(f);
                default -> null;
            };

            if (metadata == null) return;

            class Info {
                // boolean isPrgFileType;
                long offset;
                long address;
                long size;

                public Info(/*boolean isPrgFileType, */long offset, long address, long size) {
                    // this.isPrgFileType = isPrgFileType;
                    this.offset = offset;
                    this.address = address;
                    this.size = size;
                }
            }

            // Get the info needed for loading the file

            Info info = switch (metadata) {
                case D80Entry d80 -> d80.filetype == CommodoreD80FileSystem.D80_FILETYPE_PRG
                    ? new Info(2, (provider.readByte(0) & 0xFF) | ((provider.readByte(1) & 0xFF) << 8), d80.size - 2)
                    : new Info(0, 0, d80.size);
                default -> null;
            };

            if (info == null) return;

            // set up the memory, symbols, and entry point

            AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
            Address loadAddress = addressSpace.getAddress(info.address);

            program.getMemory().createInitializedBlock(
                "CODE",                                                         // name
                loadAddress,                                                    // start
                MemoryBlockUtils.createFileBytes(program, provider, monitor),   // filebytes
                info.offset,                                                    // offset
                info.size,                                                      // size
                false                                                           // overlay
            );

            if (info.address != 0) {
                SymbolTable st = program.getSymbolTable();
                st.createLabel(loadAddress, "entry", SourceType.ANALYSIS);
                st.addExternalEntryPoint(loadAddress);
            }
    
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}