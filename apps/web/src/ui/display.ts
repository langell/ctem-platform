/** Presentational helpers for the Designer UI spec. No scoring. */

/** Title-case a snake_case token: not_validated -> Not validated. */
export function humanize(value: string): string {
  const spaced = value.replace(/_/g, ' ');
  if (!spaced) return spaced;
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export type ScoreBand = 'high' | 'mid' | 'low';

/** ≥70 danger, 40–69 warn, <40 ok. */
export function scoreBand(score: number): ScoreBand {
  if (score >= 70) return 'high';
  if (score >= 40) return 'mid';
  return 'low';
}

export function scoreClass(score: number): string {
  return `score-${scoreBand(score)}`;
}

/** 12% tint cell fill for the Findings list Risk column. */
export function riskBandClass(score: number): string {
  return `risk-band-${scoreBand(score)}`;
}

/** 3px inset left rail on Findings list data rows. */
export function severityRailClass(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'rail-danger';
    case 'high':
      return 'rail-warn';
    case 'medium':
      return 'rail-accent';
    case 'low':
    case 'info':
      return 'rail-info';
    default:
      return 'rail-muted';
  }
}

export function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'badge badge-danger';
    case 'high':
      return 'badge badge-warn';
    case 'medium':
      return 'badge badge-accent';
    case 'low':
      return 'badge badge-info';
    default:
      return 'badge badge-muted';
  }
}

export function validationBadgeClass(validation: string): string {
  switch (validation) {
    case 'exploitable':
      return 'badge badge-danger';
    case 'reachable':
      return 'badge badge-warn';
    case 'not_validated':
      return 'badge badge-muted';
    default:
      return 'badge badge-muted';
  }
}

export function exposureBadgeClass(exposure: string): string {
  return exposure === 'internet_facing' ? 'badge badge-danger' : 'badge badge-muted';
}

export function contributionBarWidth(contribution: number): string {
  return `${Math.min(100, Math.abs(contribution) * 100)}%`;
}

/** Whole-score points, not toFixed(3) as the glyph. */
export function formatContribution(contribution: number): string {
  return String(Math.round(contribution * 100));
}
