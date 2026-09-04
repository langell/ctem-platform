import { describe, expect, it } from 'vitest';
import {
  contributionBarWidth,
  exposureBadgeClass,
  formatContribution,
  humanize,
  riskBandClass,
  scoreBand,
  scoreClass,
  severityBadgeClass,
  severityRailClass,
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
    expect(riskBandClass(94)).toBe('risk-band-high');
    expect(riskBandClass(61)).toBe('risk-band-mid');
    expect(riskBandClass(28)).toBe('risk-band-low');
  });
});

describe('findings score rail', () => {
  it('maps fixture severity to rail classes', () => {
    expect(severityRailClass('critical')).toBe('rail-danger');
    expect(severityRailClass('high')).toBe('rail-warn');
    expect(severityRailClass('medium')).toBe('rail-accent');
    expect(severityRailClass('low')).toBe('rail-info');
    expect(severityRailClass('info')).toBe('rail-info');
    expect(severityRailClass('unknown')).toBe('rail-muted');
    expect(severityRailClass('other')).toBe('rail-muted');
  });
});

describe('badges and labels', () => {
  it('title-cases snake_case without inventing copy', () => {
    expect(humanize('not_validated')).toBe('Not validated');
    expect(humanize('internet_facing')).toBe('Internet facing');
    expect(humanize('cloud_posture')).toBe('Cloud posture');
    expect(humanize('fail_build')).toBe('Fail build');
    expect(humanize('queued')).toBe('Queued');
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
