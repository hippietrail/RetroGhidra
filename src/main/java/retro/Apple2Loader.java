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
import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.nio.file.FileSystem;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
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
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import retro.Apple2Binary2FileSystem;
import retro.Apple2Dos3DskFileSystem;
import retro.Apple2PascalDskFileSystem;
import retro.Apple2ProDosDskFileSystem;

/**
* A {@link Loader} for loading Apple II files from RetroGhidra {@link FileSystem}s.
*/
public class Apple2Loader extends AbstractProgramWrapperLoader {

    private static final String AII_NAME = "Apple II";
    // FSRLs call these "protocols" but FileSystems call them "types"
    private static final String[] PROTOCOLS = {
        Apple2Binary2FileSystem.FS_TYPE,
        // Apple2CpmFileSystem.FS_TYPE,
        Apple2Dos3DskFileSystem.FS_TYPE,
        Apple2PascalDskFileSystem.FS_TYPE,
        Apple2ProDosDskFileSystem.FS_TYPE,
    };

    @Override
    public String getName() {
        return AII_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List <LoadSpec> loadSpecs = new ArrayList <>();

        String protocol = provider.getFSRL().getFS().getProtocol();

        if (Arrays.asList(PROTOCOLS).contains(protocol)) {
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
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
            GFileSystem afs = rf.fsRef.getFilesystem();
            GFile f = afs.lookup(provider.getFSRL().getPath());

            Object metadata = switch (afs) {
                case Apple2Binary2FileSystem fs -> fs.getMetadata(f);
                case Apple2Dos3DskFileSystem fs -> fs.getMetadata(f);
                case Apple2PascalDskFileSystem fs -> fs.getMetadata(f);
                case Apple2ProDosDskFileSystem fs -> fs.getMetadata(f);
                default -> null;
            };

            if (metadata == null) return;

            class Info {
                String filetype;
                long offset;
                long address;
                long size;

                public Info(String filetype, long offset, long address, long size) {
                    this.filetype = filetype;
                    this.offset = offset;
                    this.address = address;
                    this.size = size;
                }
            }

            // Get the info needed for loading the file

            Info entry = switch (metadata) {
                case BnyEntry bny -> new Info(
                        // might need to do different things for different os type / file type combos
                        Apple2Binary2FileSystem.filetypeToString(bny.filetypeCode),
                        0,
                        bny.auxTypeCode,
                        bny.size
                    );
                case Dos3Entry dos3 -> new Info(
                        Apple2Dos3DskFileSystem.filetypeToString(dos3.fileType),
                        2 * 2, // skip the address and size
                        (provider.readByte(0) & 0xFF) | ((provider.readByte(1) & 0xFF) << 8),
                        (provider.readByte(2) & 0xFF) | ((provider.readByte(3) & 0xFF) << 8)
                    );
                case ProDosEntry pro -> new Info(
                        Apple2ProDosDskFileSystem.fileTypeToString(pro.fileType),
                        0,
                        pro.auxType,
                        pro.size
                    );
                default -> null;
            };

            if (entry == null) return;

            // set up the memory, symbols, and entry point

            AddressSpace adsp = program.getAddressFactory().getDefaultAddressSpace();
            Address loadAndStart = adsp.getAddress(entry.address);

            program.getMemory().createInitializedBlock(
                "CODE",
                loadAndStart,
                MemoryBlockUtils.createFileBytes(program, provider, monitor),
                entry.offset,
                entry.size,
                false
            );

            SymbolTable st = program.getSymbolTable();
            st.createLabel(loadAndStart, "entry", SourceType.ANALYSIS);
            st.addExternalEntryPoint(loadAndStart);

        } catch (Exception e) {
            log.appendException(e);
        }
    }
}