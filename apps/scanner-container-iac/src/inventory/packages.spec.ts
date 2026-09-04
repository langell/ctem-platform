import { describe, expect, it } from 'vitest';
import { inventoryImage, parseApkInstalled, ContainerInventoryError } from './packages';
import type { LayerSnapshot } from '../oci/registry';

const BASE = `sha256:${'b'.repeat(64)}`;
const APP = `sha256:${'c'.repeat(64)}`;

function layer(digest: string, files: Record<string, string>): LayerSnapshot {
  return {
    digest,
    mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
    files: new Map(Object.entries(files).map(([path, body]) => [path, Buffer.from(body)])),
    whiteouts: [],
    opaqueDirs: [],
  };
}

describe('parseApkInstalled', () => {
  it('reads P:/V: records', () => {
    const pkgs = parseApkInstalled('P:openssl\nV:1.1.1w\n\nP:busybox\nV:1.36.1\n\n', 'lib/apk/db/installed', BASE);
    expect(pkgs.map((p) => `${p.name}@${p.version}`).sort()).toEqual(['busybox@1.36.1', 'openssl@1.1.1w']);
    expect(pkgs[0]?.layerDigest).toBe(BASE);
  });
});

describe('inventoryImage', () => {
  it('keeps OS introducer across a later DB rewrite that does not change the package', () => {
    const pkgs = inventoryImage([
      layer(BASE, { 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' }),
      layer(APP, {
        'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\nP:busybox\nV:1.36.1\n\n',
        'app/node_modules/lodash/package.json': '{"name":"lodash","version":"4.17.21"}',
      }),
    ]);
    const openssl = pkgs.find((p) => p.name === 'openssl');
    const busybox = pkgs.find((p) => p.name === 'busybox');
    const lodash = pkgs.find((p) => p.name === 'lodash');
    expect(openssl?.layerDigest).toBe(BASE);
    expect(busybox?.layerDigest).toBe(APP);
    expect(lodash?.layerDigest).toBe(APP);
    expect(lodash?.ecosystem).toBe('npm');
  });

  it('throws on an RPM database rather than skipping it', () => {
    expect(() => inventoryImage([layer(BASE, { 'var/lib/rpm/Packages': 'x' })])).toThrow(
      ContainerInventoryError,
    );
  });

  it('returns zero packages for a complete walk with no inventory files', () => {
    expect(inventoryImage([layer(BASE, { 'etc/os-release': 'ID=scratch\n' })])).toEqual([]);
  });
});
