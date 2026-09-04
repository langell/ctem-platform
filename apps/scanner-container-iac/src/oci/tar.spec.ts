import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { decompressLayer, parseTar, LayerUnpackError } from './tar';
import { packTar, tarHeaderOnly } from './test-tar';

describe('decompressLayer', () => {
  it('gunzips gzip layers and rejects zstd', () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1\n' });
    const gz = gzipSync(tar);
    expect(decompressLayer(gz, 'application/vnd.oci.image.layer.v1.tar+gzip').equals(tar)).toBe(true);
    expect(() => decompressLayer(Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x00]), 'tar+zstd')).toThrow(
      LayerUnpackError,
    );
  });
});

describe('parseTar', () => {
  it('reads files and whiteouts', () => {
    const tar = packTar({
      'lib/apk/db/installed': 'P:openssl\nV:1.1.1\n',
      'app/.wh.removed': '',
    });
    const entries = parseTar(tar);
    const files = entries.filter((e) => e.type === 'file');
    expect(files.some((e) => e.name === 'lib/apk/db/installed')).toBe(true);
    expect(entries.some((e) => e.type === 'whiteout' && e.name === 'app/removed')).toBe(true);
  });

  it('throws on a truncated payload instead of returning a partial walk', () => {
    const header = tarHeaderOnly('lib/apk/db/installed', 100);
    expect(() => parseTar(header)).toThrow(/Truncated tar payload/);
  });
});
