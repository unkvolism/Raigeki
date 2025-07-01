# Raigeki

<p align="center">
  <img src="https://static.wikia.nocookie.net/yugioh/images/1/11/Raigeki-TF04-JP-VG.png/revision/latest?cb=20161225202122" alt="Raigeki" width="300"/>
</p>

**Raigeki** is a shellcode loader written in **Rust**, implementing a custom memory writing technique using **Asynchronous Procedure Calls (APCs)** with `NtQueueApcThread` and `RtlFillMemory`.

This project is a **Rust reimplementation** of the technique originally demonstrated in C by [x86matthew](https://www.x86matthew.com/view_post?id=writeprocessmemory_apc).  
Full credit for the concept and original implementation goes to him.

---

## Technique Overview

Normally, the Windows API function `QueueUserAPC` only allows queuing APCs with a **single argument**, which limits its usefulness for tasks like arbitrary memory writing. Internally, however, it calls the undocumented function `NtQueueApcThread`, which supports **three arguments** for the callback.

This gives us the ability to call functions such as `RtlFillMemory(ptr, len, value)` directly from an APC and allows for writing data byte-by-byte without relying on `WriteProcessMemory`.

### How it works:

1. **Resolve the address of `RtlFillMemory`** dynamically.
2. **Create a suspended thread** in the target process using `NtCreateThreadEx`, with a safe or dummy entry point.
3. **Queue APCs** to the thread using `NtQueueApcThread`, each pointing to `RtlFillMemory`, specifying the destination address, size (`1`), and value (byte).
4. **Resume the thread**, allowing it to process the APC queue and execute each `RtlFillMemory` call to perform the write.

This results in a full buffer being written byte-by-byte through APCs, offering an alternative to traditional `WriteProcessMemory` that may bypass basic memory write detections.

---

## What Raigeki Does

Raigeki is a simple proof-of-concept shellcode loader that:

- Reads shellcode from a binary file.
- Allocates memory with `VirtualAlloc`.
- Uses the custom `WriteProcessMemoryAPC` function to write the shellcode into memory, byte-by-byte via `RtlFillMemory`.
- Changes memory protection to `PAGE_EXECUTE_READWRITE`.
- Creates a local thread to execute the shellcode.

---


## Build Instructions

```bash
# Clone the repository
git clone https://github.com/unkvolism/raigeki.git
cd raigeki

# Build in release mode
cargo build --release

# Run with the path to your shellcode binary
cargo run --release -- ./shellcode.bin
