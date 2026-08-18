/**
 * Big-endian binary buffer reader and builder for Tor wire formats.
 */

export class BufferReader {
  private view: DataView;
  private offset = 0;

  constructor(private buffer: Uint8Array) {
    this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  }

  get remaining(): number {
    return this.buffer.length - this.offset;
  }

  get currentOffset(): number {
    return this.offset;
  }

  readUint8(): number {
    if (this.offset + 1 > this.buffer.length) {
      throw new Error(`Buffer underflow reading Uint8 at offset ${this.offset}`);
    }
    const val = this.view.getUint8(this.offset);
    this.offset += 1;
    return val;
  }

  readUint16(): number {
    if (this.offset + 2 > this.buffer.length) {
      throw new Error(`Buffer underflow reading Uint16 at offset ${this.offset}`);
    }
    const val = this.view.getUint16(this.offset, false);
    this.offset += 2;
    return val;
  }

  readUint32(): number {
    if (this.offset + 4 > this.buffer.length) {
      throw new Error(`Buffer underflow reading Uint32 at offset ${this.offset}`);
    }
    const val = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return val;
  }

  readBytes(length: number): Uint8Array {
    if (this.offset + length > this.buffer.length) {
      throw new Error(`Buffer underflow reading ${length} bytes at offset ${this.offset}`);
    }
    const slice = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  readRemaining(): Uint8Array {
    const slice = this.buffer.subarray(this.offset);
    this.offset = this.buffer.length;
    return slice;
  }

  readString(length: number): string {
    const bytes = this.readBytes(length);
    return new TextDecoder().decode(bytes);
  }

  readCString(): string {
    let end = this.offset;
    while (end < this.buffer.length && this.buffer[end] !== 0) {
      end++;
    }
    const str = new TextDecoder().decode(this.buffer.subarray(this.offset, end));
    this.offset = end < this.buffer.length ? end + 1 : end;
    return str;
  }
}

export class BufferWriter {
  private chunks: Uint8Array[] = [];
  private totalLength = 0;

  writeUint8(value: number): this {
    const buf = new Uint8Array(1);
    buf[0] = value & 0xff;
    this.chunks.push(buf);
    this.totalLength += 1;
    return this;
  }

  writeUint16(value: number): this {
    const buf = new Uint8Array(2);
    new DataView(buf.buffer).setUint16(0, value, false);
    this.chunks.push(buf);
    this.totalLength += 2;
    return this;
  }

  writeUint32(value: number): this {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, value, false);
    this.chunks.push(buf);
    this.totalLength += 4;
    return this;
  }

  writeBytes(data: Uint8Array): this {
    this.chunks.push(data);
    this.totalLength += data.length;
    return this;
  }

  writeString(str: string): this {
    const bytes = new TextEncoder().encode(str);
    this.chunks.push(bytes);
    this.totalLength += bytes.length;
    return this;
  }

  writeZeroes(length: number): this {
    this.chunks.push(new Uint8Array(length));
    this.totalLength += length;
    return this;
  }

  writeCString(str: string): this {
    this.writeString(str);
    this.writeUint8(0);
    return this;
  }

  get length(): number {
    return this.totalLength;
  }

  toUint8Array(): Uint8Array {
    const result = new Uint8Array(this.totalLength);
    let offset = 0;
    for (const chunk of this.chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }
}
