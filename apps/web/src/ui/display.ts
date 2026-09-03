/** Presentational helpers for the Designer's first-pass UI spec. No scoring. */

export function humanize(value: string): string {
  return value.replace(/_/g, ' ');
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
