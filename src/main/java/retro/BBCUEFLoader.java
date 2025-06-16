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

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import com.google.gson.Gson;

import ghidra.framework.Application;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import retro.UEF.*;

/**
 * UEF loader for BBC / Electron
 */
public class BBCUEFLoader extends AbstractProgramWrapperLoader {
	
    private static final String BBC_UEF_NAME = "BBC Micro / Election (UEF)";
    private static final String BBC_UEF_MAGIC = "UEF File!";

	private String getROMPath() throws IOException {
		String path = Application.getModuleDataFile("UEF/os12.rom").toString();
		return path;
	}
	
	private String getVariablePath() throws IOException {
		String path = Application.getModuleDataFile("UEF/labels.json").toString();
		return path;
	}
	
    @Override
    public String getName() {
        return BBC_UEF_NAME;
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

		BinaryReader reader = new BinaryReader(provider, true);
		
		// read header
		String magic = reader.readAsciiString(0, 10);
		if (magic.equals(BBC_UEF_MAGIC))
		{
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// Load in the OS file
		InputStream ROMFile = new FileInputStream(getROMPath());
		byte []ROMdata = ROMFile.readAllBytes();
		ROMFile.close();
		
		// Load in the predefined OS labels and functions
		Gson gson = new Gson();
		GhidraLabel[] labels = gson.fromJson(new FileReader(getVariablePath()), GhidraLabel[].class);

		// Read the file
		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		UEF UEFFile = new UEF(reader);
		
		// Now we have it loaded - it's time to create some objects
		try {
			if (UEFFile.ram != null) api.createMemoryBlock("RAM", api.toAddr(0), UEFFile.ram, false);
			MemoryBlock block = api.createMemoryBlock("ROM", api.toAddr(0xC000), ROMdata, false);
			block.setRead(true);
			block.setExecute(true);
			
			if ((UEFFile.cpustate.PC & 0xffff) < 0x8000) {
				// PC is in RAM so add it as an Entrypoint
				api.addEntryPoint(api.toAddr(UEFFile.cpustate.PC & 0xffff));
			}
			
			// Create some standard functions
			for (GhidraLabel label : labels) {
				switch(label.getType()) {
				case "Function":
					api.createFunction(api.toAddr(label.getAddress()), label.getName());
					break;
					
				case "Pointer":
					api.createData(api.toAddr(label.getAddress()), Pointer16DataType.dataType);
					api.createLabel(api.toAddr(label.getAddress()), label.getName(), true);
					break;
				}
			}
			
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
		
	}

}
