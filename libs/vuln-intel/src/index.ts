export { VulnMatcher, type VulnMatch, type MatchResult, type MatchableComponent } from './vuln.matcher';
export { versionAffected, compareVersions, type OsvAffected } from './osv-range';
export {
  fetchEpssPaged,
  parseEpssPage,
  nextEpssOffset,
  EPSS_PAGE_SIZE,
  EPSS_CVE_BATCH,
  EPSS_MAX_PAGES,
  type EpssScore,
  type EpssPage,
  type EpssFetchOptions,
} from './epss.client';
