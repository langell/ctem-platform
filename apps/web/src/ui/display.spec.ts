import { describe, expect, it } from 'vitest';
import {
  contributionBarWidth,
  exposureBadgeClass,
  formatContribution,
  humanize,
  scoreBand,
  scoreClass,
  severityBadgeClass,
  validationBadgeClass,
} from './display';

describe('score bands', () => {
  it('maps ≥70 danger, 40–69 warn, <40 ok', () => {
    expect(scoreBand(100)).toBe('high');
    expect(scoreBand(70)).toBe('high');
    expect(scoreBand(69)).toBe('mid');
    expect(scoreBand(40)).toBe('mid');
    expect(scoreBand(39)).toBe('low');
    expect(scoreBand(0)).toBe('low');
    expect(scoreClass(88)).toBe('score-high');
    expect(scoreClass(55)).toBe('score-mid');
    expect(scoreClass(12)).toBe('score-low');
  });
});

describe('badges and labels', () => {
  it('humanizes snake_case without inventing copy', () => {
    expect(humanize('not_validated')).toBe('not validated');
    expect(humanize('internet_facing')).toBe('internet facing');
    expect(humanize('cloud_posture')).toBe('cloud posture');
  });

  it('maps severity and validation to the spec tints', () => {
    expect(severityBadgeClass('critical')).toBe('badge badge-danger');
    expect(severityBadgeClass('high')).toBe('badge badge-warn');
    expect(severityBadgeClass('medium')).toBe('badge badge-accent');
    expect(severityBadgeClass('low')).toBe('badge badge-info');
    expect(validationBadgeClass('exploitable')).toBe('badge badge-danger');
    expect(validationBadgeClass('reachable')).toBe('badge badge-warn');
    expect(validationBadgeClass('not_validated')).toBe('badge badge-muted');
    expect(exposureBadgeClass('internet_facing')).toBe('badge badge-danger');
    expect(exposureBadgeClass('internal')).toBe('badge badge-muted');
  });

  it('renders contribution as a bar width plus whole points, not toFixed(3)', () => {
    expect(contributionBarWidth(0.25)).toBe('25%');
    expect(contributionBarWidth(1.5)).toBe('100%');
    expect(formatContribution(0.123)).toBe('12');
    expect(formatContribution(-0.05)).toBe('-5');
  });
});
