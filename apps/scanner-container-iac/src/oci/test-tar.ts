/** Test-only ustar packer. Production unpack lives in tar.ts. */

function tarHeader(name: string, size: number, typeflag = '0'): Buffer {
  const buf = Buffer.alloc(512);
  buf.write(name.slice(0, 100));
  buf.write('0000644', 100);
  const sizeOct = size.toString(8).padStart(11, '0');
  buf.write(`${sizeOct}\0`, 124);
  buf.write(typeflag, 156);
  buf.write('ustar\0', 257);
  buf.write('        ', 148);
  let sum = 0;
  for (const b of buf) sum += b;
  buf.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  return buf;
}

export function packTar(files: Record<string, string>): Buffer {
  const chunks: Buffer[] = [];
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    chunks.push(tarHeader(name, data.length), data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad) chunks.push(Buffer.alloc(pad));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

export function tarHeaderOnly(name: string, size: number): Buffer {
  return tarHeader(name, size);
}
