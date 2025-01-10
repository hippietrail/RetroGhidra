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
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.PascalStringDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Sinclair QL QDOS executable files.
 */
public class QlLoader extends AbstractProgramWrapperLoader {

    public static final String QDOS_NAME = "Sinclair QL QDOS";
    public static final int QDOS_OFF_SIG = 6;
    public static final int QDOS_OFF_FILENAME = 8;
    public static final int QDOS_HEADER_LEN = 64;
    public static final int QDOS_SIG = 0x4afb;
    public static final int QDOS_FILENAME_LEN = 36;
    public static final int QDOS_PREFERRED_LOAD_ADDR = 0x30000;

    @Override
    public String getName() {
        return QDOS_NAME;
    }

    // lower numbers have higher priority
    // 50 seems to be standard, raw uses 100
    // RetroGhidra Loaders that don't have magic numbers should use 60
    @Override
    public int getTierPriority() {
        return 60;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        if (provider.length() < QDOS_HEADER_LEN) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, false);

        if (reader.readUnsignedShort(QDOS_OFF_SIG) != QDOS_SIG) return loadSpecs;
        // filename field is apparently optional and doesn't prevent files being loaded and ran
        //   but QL filenames are max 36 chars long
        // if we still get false positives we can check that each char is 7-bit ASCII [0x20-0x80)
        if (reader.readUnsignedShort(QDOS_OFF_FILENAME) > QDOS_FILENAME_LEN) return loadSpecs;

        List<QueryResult> queryResults = QueryOpinionService.query(getName(), "68000", null);
        queryResults.stream().map(result -> new LoadSpec(this, 0, result)).forEach(loadSpecs::add);

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        try {
            Memory memory = program.getMemory();
            AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
            FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

            // QL programs are usually relocatable, but for non-relocatable programs
            // I've seen a load address of 196608 (0x30000) reccomended.
            Address loadAddress = addressSpace.getAddress(QDOS_PREFERRED_LOAD_ADDR);

            memory.createInitializedBlock("TEXT", loadAddress, fileBytes, 0, provider.length(), false).setWrite(true); // QL has no memory protection

            SymbolTable st = program.getSymbolTable();
            Listing listing = program.getListing();

            st.createLabel(loadAddress, "entry", SourceType.IMPORTED);
            st.addExternalEntryPoint(loadAddress);

            Address sigAddress = loadAddress.add(QDOS_OFF_SIG);
            st.createLabel(sigAddress, "signature", SourceType.IMPORTED);
            listing.createData(sigAddress, UnsignedShortDataType.dataType);

            Address filenameAddress = loadAddress.add(QDOS_OFF_FILENAME);
            st.createLabel(filenameAddress, "filename", SourceType.IMPORTED);
            listing.createData(filenameAddress, PascalStringDataType.dataType);
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}