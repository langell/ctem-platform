import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { EventBus } from '@ctem/events';
import { FindingsReportedPayload, SUBJECTS } from '@ctem/contracts';
import { FindingsService } from './findings.service';

@Injectable()
export class FindingIngestConsumer implements OnApplicationBootstrap {
  constructor(
    private readonly bus: EventBus,
    private readonly findings: FindingsService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.bus.subscribe(
      SUBJECTS.findingsReported,
      // Ingest is the hottest path in the system; give it room to retry and a
      // generous ack window for scanners that report thousands of findings.
      { durable: 'findings-ingest', maxDeliver: 5, ackWaitMs: 120_000 },
      async (payload, envelope) => {
        const parsed = FindingsReportedPayload.parse(payload);
        await this.findings.ingest(envelope.orgId, parsed);
      },
    );
  }
}
