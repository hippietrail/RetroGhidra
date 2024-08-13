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
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Apple II files with NAPS (NuLib2 attribute preservation strings).
 */
public class Apple2NapsLoader extends AbstractProgramWrapperLoader {

    public static final String NAPS_NAME = "Apple II binary with NAPS";

	@Override
	public String getName() {
        return NAPS_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

        String name = provider.getName();
        if (name.indexOf('#') < 0) return loadSpecs;
        String naps = name.substring(name.lastIndexOf('#') + 1);
        if (naps.length() != 6) return loadSpecs;
        if (!naps.matches("[0-9a-fA-F]{6}")) return loadSpecs;
        if (!naps.substring(0, 2).equals("06")) return loadSpecs;

        // 6502:LE:16:default

        List<QueryResult> queryResults = QueryOpinionService.query(getName(), "6502", null);
        queryResults.forEach(result -> loadSpecs.add(new LoadSpec(this, 0, result)));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

        String name = provider.getName();
        String naps = name.substring(name.lastIndexOf('#') + 1);

        final int start = Integer.parseInt(naps.substring(2), 16);

        Address startAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(start);
        SymbolTable st = program.getSymbolTable();

        try {
            program.getMemory().createInitializedBlock(
                "CODE",
                startAddress,
                MemoryBlockUtils.createFileBytes(program, provider, monitor),
                0,
                provider.length(),
                false
            ).setWrite(true);

            st.createLabel(startAddress, "entry", SourceType.IMPORTED);
            st.addExternalEntryPoint(startAddress);
        } catch (Exception e) {
            log.appendException(e);
        }
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
