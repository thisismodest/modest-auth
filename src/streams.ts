// Reading a stream with a limit, so nothing sent to the server (or fetched by it) can fill its memory.

/**
 * A stream's bytes, up to `most`; "too-large" past it. Either way, or when `signal` aborts, the
 * stream is let go (cancelled), so nobody can keep sending into it. Throws if the stream fails.
 */
export async function readAtMost(stream: ReadableStream<Uint8Array> | null | undefined, most: number, signal?: AbortSignal): Promise<Buffer | "too-large"> {
  const reader = stream?.getReader();
  if (!reader) return Buffer.alloc(0);
  const stop = () => void reader.cancel().catch(() => {});
  signal?.addEventListener("abort", stop, { once: true });
  try {
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (let part = await reader.read(); !part.done; part = await reader.read()) {
      size += part.value.byteLength;
      if (size > most) {
        stop();
        return "too-large";
      }
      chunks.push(part.value);
    }
    return Buffer.concat(chunks);
  } finally {
    signal?.removeEventListener("abort", stop);
  }
}
