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

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Sinclair ZX Spectrum Snapshot (SNA) files.
 */
public class SpectrumSnaLoader extends AbstractProgramWrapperLoader {

	public static final String ZX_SNA_NAME = "Sinclair ZX Spectrum Snapshot (SNA)";
	public static final long ZX_SNA_LENGTH_48K = 27 + 48 * 1024;
	public static final long ZX_SNA_LENGTH_128K_S = 27 + 48 * 1024 + 4 + 5 * 16 * 1024;
	public static final long ZX_SNA_LENGTH_128K_L = 27 + 48 * 1024 + 4 + 6 * 16 * 1024;
	public static final Long[] ZX_SNA_LENGTHS = {
		ZX_SNA_LENGTH_48K,
		ZX_SNA_LENGTH_128K_S, // short: no repeated 16k bank
		ZX_SNA_LENGTH_128K_L, // long: has repeated 16k bank
	};
	public static final int ZX_SNA_OFF_IFF2 = 0x13;

	@Override
	public String getName() {
		return ZX_SNA_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		
		// use a temp since .length() can throw and .anyMatch() is a lambda (no 'throws' clause)
		Long fileLength = reader.length();
		if (!Arrays.stream(ZX_SNA_LENGTHS).anyMatch(length -> length.equals(fileLength))) return loadSpecs;

		// only 1 bit of this field is defined, anything else probably a false positive
		int iff2 = reader.readUnsignedByte(ZX_SNA_OFF_IFF2);
		if ((iff2 & ~0b0000_0100) != 0) return loadSpecs;

		// stack pointer can't be in ROM, probably a false positive
		int sp = reader.readUnsignedShort(0x17);
		if (sp < 16384) Msg.warn(this, "Stack pointer in ROM");

		// only 0 to 2 are valid, anything else probably a false positive
		int interruptMode = reader.readUnsignedByte(0x19);
		if (interruptMode > 2) return loadSpecs;

		// .SNA was originally used by a hardware device. This field indicated Sinclair Interface 1 presence
		// As an emulator format, this field indicates border colour, only 0 to 7
		// Anything besides these 8 values probably a false positive
		int borderColourOrInt1 = reader.readUnsignedByte(0x1A);
		if (borderColourOrInt1 > 7 && borderColourOrInt1 != 0x71 && borderColourOrInt1 != 0xC9)
			return loadSpecs;

		List<QueryResult> queryResults = QueryOpinionService.query(getName(), "z80", null);
		queryResults.stream().map(result -> new LoadSpec(this, 0, result)).forEach(loadSpecs::add);

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		if (provider.length() != ZX_SNA_LENGTH_48K) {
			Msg.error(this, "Only 48K SNA snapshots are supported so far.");
			return;
		}

		BinaryReader reader = new BinaryReader(provider, true);

		// in 48k snapshots, pc is on the stack
		// TODO use optionals?
		int sp = reader.readUnsignedShort(0x17);
		boolean spOK = sp >= 16384;
		boolean pcOK = false;
		int pc = -1;
		if (spOK) {
			pc = reader.readUnsignedShort(0x1b + sp - 16384);
			sp = (sp + 2) & 0xffff;
		}
		pcOK = pc >= 16384;

		if (pcOK) Msg.info(this, "SP = " + Integer.toHexString(sp) + ", PC = " + Integer.toHexString(pc));
		else Msg.warn(this, "SP = " + Integer.toHexString(sp) + ", PC = ?");

		try {
			int bitmapStart = 16384; // 0x4000
			int bitmapLen = 32 * 192;
			int attributeStart = 16384 + bitmapLen;
			int attributeLen = 32 * 24;
			int attributeEnd = attributeStart + attributeLen;
			int restart = attributeEnd;
			int restEnd = 0x10000;
			int restLen = restEnd - restart;

			// TODO doesn't need to be initialized to all 0xff, not sure all the APIs available

			Address bitmapAdd = program.getAddressFactory().getDefaultAddressSpace().getAddress(bitmapStart);
			MemoryBlock bitmapBlock = program.getMemory().createInitializedBlock("bitmap", bitmapAdd, bitmapLen, (byte) 0x0f, monitor, false);
			bitmapBlock.setWrite(true);

			Address attrAdd = program.getAddressFactory().getDefaultAddressSpace().getAddress(attributeStart);
			MemoryBlock attrBlock = program.getMemory().createInitializedBlock("attributes", attrAdd, attributeLen, (byte) 0xf0, monitor, false);
			attrBlock.setWrite(true);

			Address restAdd = program.getAddressFactory().getDefaultAddressSpace().getAddress(restart);
			MemoryBlock restBlock = program.getMemory().createInitializedBlock("rest", restAdd, restLen, (byte) 0xaa, monitor, false);
			restBlock.setWrite(true);

			Address ramAdd = bitmapAdd;
			
			reader.setPointerIndex(0x1b);
			byte[] codeBytes = reader.readByteArray(0x1b, 48 * 1024);
			program.getMemory().setBytes(ramAdd, codeBytes);

			if (pcOK) {
				Address ep = program.getAddressFactory().getDefaultAddressSpace().getAddress(pc);	
				SymbolTable st = program.getSymbolTable();
				st.createLabel(ep, "entry", SourceType.ANALYSIS);
				st.addExternalEntryPoint(ep);
			}

			if (spOK) {
				Address spAdd = program.getAddressFactory().getDefaultAddressSpace().getAddress(sp);
				SymbolTable st = program.getSymbolTable();
				st.createLabel(spAdd, "stack", SourceType.ANALYSIS);
			}
		} catch (Exception e) {
			log.appendException( e );
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
