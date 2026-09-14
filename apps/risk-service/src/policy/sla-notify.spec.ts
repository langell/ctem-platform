import { describe, expect, it } from 'vitest';
import { slaNotifyResetForDueChange } from './sla-notify';

describe('slaNotifyResetForDueChange', () => {
  const earlier = new Date('2026-01-01T00:00:00.000Z');
  const later = new Date('2026-01-02T00:00:00.000Z');

  it('clears the claim when slaDueAt becomes null', () => {
    expect(slaNotifyResetForDueChange(earlier, null)).toEqual({ slaNotifiedAt: null });
  });

  it('clears the claim when slaDueAt moves later than the prior due', () => {
    expect(slaNotifyResetForDueChange(earlier, later)).toEqual({ slaNotifiedAt: null });
  });

  it('does not clear when slaDueAt is first assigned', () => {
    expect(slaNotifyResetForDueChange(null, later)).toEqual({});
    expect(slaNotifyResetForDueChange(undefined, later)).toEqual({});
  });

  it('does not clear when slaDueAt is unchanged or tightened', () => {
    expect(slaNotifyResetForDueChange(later, later)).toEqual({});
    expect(slaNotifyResetForDueChange(later, earlier)).toEqual({});
  });
});
