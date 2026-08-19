import type { RawFinding, ScanJob, ScannerType } from '@ctem/contracts';

export interface ScanContext {
  job: ScanJob;
  /** Scratch directory the worker cleans up after the run. */
  workDir: string;
  /** Called periodically; throw if it returns false to abort a job past its deadline. */
  checkDeadline: () => boolean;
  log: (msg: string, meta?: Record<string, unknown>) => void;
}

export interface ScanOutcome {
  findings: RawFinding[];
  /** Raw tool output persisted to object storage as evidence. */
  rawOutput?: unknown;
  stats?: Record<string, number>;
}

/**
 * Every scanner implements this and nothing else. Queue plumbing, retries,
 * artifact upload, tenancy and event publication are handled by ScannerWorker,
 * so adding a new scanner is a matter of writing `execute`.
 */
export abstract class BaseScanner {
  abstract readonly type: ScannerType;
  abstract readonly name: string;
  abstract readonly version: string;

  /** Cheap check to skip assets this scanner cannot handle. */
  supports(_job: ScanJob): boolean {
    return true;
  }

  abstract execute(ctx: ScanContext): Promise<ScanOutcome>;

  /** Optional warm-up: pull rule packs, refresh feeds, verify the CLI is present. */
  async onReady(): Promise<void> {
    return;
  }
}

export const SCANNER = Symbol('CTEM_SCANNER');
