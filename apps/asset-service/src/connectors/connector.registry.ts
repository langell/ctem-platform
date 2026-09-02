import { Injectable } from '@nestjs/common';
import type { UpsertAssetRequest } from '@ctem/contracts';

export interface DiscoveryContext {
  orgId: string;
  integrationId: string;
  config: Record<string, unknown>;
  credentialRef: string | null;
  since: Date | null;
}

/**
 * Asset discovery connectors. Each one turns an external system into a stream of
 * upsert requests; the service handles persistence, archival and events.
 * GitHub, GitLab (gitlab.com or explicit `baseUrl`), AWS, and GCP are registered;
 * this remains the extension point for further providers (Azure is a later PR).
 */
export interface AssetConnector {
  readonly provider: string;
  readonly assetKinds: string[];
  discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest>;
}

@Injectable()
export class ConnectorRegistry {
  private readonly connectors = new Map<string, AssetConnector>();

  register(connector: AssetConnector): void {
    this.connectors.set(connector.provider, connector);
  }

  get(provider: string): AssetConnector | undefined {
    return this.connectors.get(provider);
  }

  list(): AssetConnector[] {
    return [...this.connectors.values()];
  }
}

/**
 * Roadmap of connectors, in the order they earn their keep:
 *   github / gitlab      -> repositories, default branches, CODEOWNERS
 *   aws / gcp            -> cloud resources, public IPs, security groups / firewalls
 *   azure                -> later cloud inventory (not this connector)
 *   kubernetes           -> workloads, images in use, ingress exposure
 *   ecr / ghcr           -> container images and tags
 *   dns + cert transparency -> external domains nobody remembers owning
 *   port scan            -> what those domains actually expose
 */
export const PLANNED_CONNECTORS = [
  'github',
  'gitlab',
  'aws',
  'azure',
  'gcp',
  'kubernetes',
  'ecr',
  'dns_enum',
  'cert_transparency',
] as const;
