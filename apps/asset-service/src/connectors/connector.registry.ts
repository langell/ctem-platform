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
 * GitHub, GitLab (gitlab.com or explicit `baseUrl`), AWS, GCP, Azure, GHCR,
 * ECR, Kubernetes (managed EKS/GKE/AKS), and DNS enum (crt.sh + OS resolver)
 * are registered; this remains the extension point for further providers.
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
 *   aws / gcp / azure    -> cloud resources, public IPs, security groups / firewalls / NSGs
 *   ghcr                 -> container images keyed by digest (Packages REST; no layer pull)
 *   ecr                  -> container images keyed by digest (ECR API; no layer pull)
 *   kubernetes           -> managed EKS/GKE/AKS clusters as kubernetes_workload
 *                           (control-plane APIs only; never kube-apiserver)
 *   dns_enum             -> org-owned apex + CT/OS names as domain
 *                           (crt.sh + OS resolver; never tenant DNS/DoH)
 *   cert transparency    -> (folded into dns_enum / ASM; not a sibling provider)
 *   port scan            -> what those domains actually expose
 */
export const PLANNED_CONNECTORS = [
  'github',
  'gitlab',
  'aws',
  'azure',
  'gcp',
  'ghcr',
  'ecr',
  'kubernetes',
  'dns_enum',
  'cert_transparency',
] as const;
