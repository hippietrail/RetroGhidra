package retro;

import java.io.IOException;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Help functions for Ghidra Loaders and, later, FileSystems
 */
public class RetroGhidra {

    /**
     * Creates a memory block from a byte provider.
     * <p>
     * This method is a convenience wrapper for the
     * {@link Memory#createInitializedBlock(String, Address, FileBytes, long, long, boolean)}
     * method.
     * <p>
     * The block is created in the default address space as a non-overlay block.
     * <p>
     * @param program the program to add the block to
     * @param provider the byte provider for the block
     * @param monitor the task monitor for the block creation
     * @param name the name of the block
     * @param byteOffset the starting address of the block
     * @param offset the offset into the byte provider
     * @param size the length of the block
     * @return the created block
     * @throws IOException if there is an error reading from the provider
     * @throws CancelledException if the task monitor is cancelled
     * @throws LockException if there is an error locking the memory
     * @throws IllegalArgumentException if the block name is null or empty
     * @throws MemoryConflictException if the block conflicts with another block
     * @throws AddressOverflowException if the block's address is out of range
     * @throws AddressOutOfBoundsException if the block's address is out of range
     */
    public static MemoryBlock createInitializedBlockFromByteProvider(
        Program program, ByteProvider provider, TaskMonitor monitor,
        String name, long byteOffset, long offset, long size)
        throws IOException, CancelledException, LockException,
            IllegalArgumentException, MemoryConflictException,
            AddressOverflowException, AddressOutOfBoundsException {

        return program.getMemory().createInitializedBlock(name,
            program.getAddressFactory().getDefaultAddressSpace().getAddress(byteOffset),
            MemoryBlockUtils.createFileBytes(program, provider, monitor),
            offset, size, false // offset, size, not overlay
        );
    }
}
