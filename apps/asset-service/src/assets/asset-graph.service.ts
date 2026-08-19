import { Injectable } from '@nestjs/common';
import { PrismaService } from '@ctem/db';

export interface GraphNode {
  id: string;
  name: string;
  kind: string;
  exposure: string;
  criticality: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: string;
  confidence: number;
}

/**
 * The graph is what makes prioritization defensible: a critical CVE in a library
 * that is only used by an internal batch job is not the same exposure as the
 * same CVE on an internet-facing API. `pathToInternet` is the query the risk
 * service leans on.
 */
@Injectable()
export class AssetGraphService {
  constructor(private readonly prisma: PrismaService) {}

  async neighborhood(
    orgId: string,
    assetId: string,
    depth = 2,
  ): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
    return this.prisma.withOrg(orgId, async (tx) => {
      // Recursive CTE beats N round-trips; RLS still applies inside the CTE.
      const rows = await tx.$queryRawUnsafe<
        Array<{ from_id: string; to_id: string; kind: string; confidence: number }>
      >(
        `WITH RECURSIVE walk(from_id, to_id, kind, confidence, depth) AS (
           SELECT e."fromAssetId", e."toAssetId", e.kind, e.confidence, 1
           FROM asset_edges e
           WHERE e."fromAssetId" = $1::uuid OR e."toAssetId" = $1::uuid
           UNION
           SELECT e."fromAssetId", e."toAssetId", e.kind, e.confidence, w.depth + 1
           FROM asset_edges e
           JOIN walk w ON e."fromAssetId" = w.to_id OR e."toAssetId" = w.from_id
           WHERE w.depth < $2
         )
         SELECT DISTINCT from_id, to_id, kind, confidence FROM walk`,
        assetId,
        depth,
      );

      const ids = new Set<string>([assetId]);
      for (const r of rows) {
        ids.add(r.from_id);
        ids.add(r.to_id);
      }

      const nodes = await tx.asset.findMany({
        where: { id: { in: [...ids] } },
        select: { id: true, name: true, kind: true, exposure: true, criticality: true },
      });

      return {
        nodes,
        edges: rows.map((r) => ({
          from: r.from_id,
          to: r.to_id,
          kind: r.kind,
          confidence: r.confidence,
        })),
      };
    });
  }

  /** True when the asset is reachable from anything classified as internet-facing. */
  async isInternetReachable(orgId: string, assetId: string, maxDepth = 4): Promise<boolean> {
    const { nodes } = await this.neighborhood(orgId, assetId, maxDepth);
    return nodes.some((n) => n.exposure === 'internet_facing');
  }

  async link(
    orgId: string,
    edge: { fromAssetId: string; toAssetId: string; kind: string; confidence?: number },
  ) {
    return this.prisma.withOrg(orgId, (tx) =>
      tx.assetEdge.upsert({
        where: {
          orgId_fromAssetId_toAssetId_kind: {
            orgId,
            fromAssetId: edge.fromAssetId,
            toAssetId: edge.toAssetId,
            kind: edge.kind,
          },
        },
        create: { orgId, ...edge, confidence: edge.confidence ?? 1 },
        update: { confidence: edge.confidence ?? 1 },
      }),
    );
  }
}
