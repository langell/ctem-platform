import { describe, expect, it } from 'vitest';
import {
  DEMO_CONTAINER_DIGEST,
  DEMO_CONTAINER_EXTERNAL_KEY,
  DEMO_CONTAINER_IMAGE,
  LEGACY_DEMO_CONTAINER_KEY,
} from './factories';

const GHCR_DIGEST_KEY = /^ghcr:[^/@]+\/.+@sha256:[a-f0-9]{64}$/i;

describe('demo container_image seed identity', () => {
  it('is digest-keyed GHCR discovery identity, not a tag stub', () => {
    expect(DEMO_CONTAINER_IMAGE.kind).toBe('container_image');
    expect(DEMO_CONTAINER_IMAGE.source).toBe('ghcr');
    expect(DEMO_CONTAINER_IMAGE.source).not.toBe('ecr');
    expect(DEMO_CONTAINER_IMAGE.externalKey).toBe(DEMO_CONTAINER_EXTERNAL_KEY);
    expect(DEMO_CONTAINER_IMAGE.externalKey).toMatch(GHCR_DIGEST_KEY);
    expect(DEMO_CONTAINER_IMAGE.externalKey).not.toMatch(/:latest$/);
    expect(DEMO_CONTAINER_IMAGE.attributes).toMatchObject({
      owner: 'demo',
      package: 'payments-api',
      digest: DEMO_CONTAINER_DIGEST,
      tags: ['latest'],
      visibility: 'public',
      packageType: 'container',
    });
    expect(DEMO_CONTAINER_DIGEST).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('keeps the legacy tag key only so re-seed can archive it', () => {
    expect(LEGACY_DEMO_CONTAINER_KEY).toBe('image:ghcr.io/demo/payments-api:latest');
    expect(LEGACY_DEMO_CONTAINER_KEY).not.toMatch(GHCR_DIGEST_KEY);
  });
});
