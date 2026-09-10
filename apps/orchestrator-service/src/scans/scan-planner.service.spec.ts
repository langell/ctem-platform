import { describe, expect, it } from 'vitest';
import { SCANNER_ASSET_KINDS } from './scan-planner.service';

describe('SCANNER_ASSET_KINDS', () => {
  it('plans container scans for container_image only — not kubernetes_workload', () => {
    expect(SCANNER_ASSET_KINDS.container).toEqual(['container_image']);
    expect(SCANNER_ASSET_KINDS.container).not.toContain('kubernetes_workload');
  });

  it('plans cloud_posture scans for cloud_resource only — not kubernetes_workload', () => {
    expect(SCANNER_ASSET_KINDS.cloud_posture).toEqual(['cloud_resource']);
    expect(SCANNER_ASSET_KINDS.cloud_posture).not.toContain('kubernetes_workload');
  });
});
