import { Body, Controller, Get, Param, Post, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, RequirePermissions } from '@ctem/auth';
import { ListAssetsQuery, UpsertAssetRequest } from '@ctem/contracts';
import { ZodBody, ZodQuery } from '@ctem/service-kit';
import { AssetsService } from './assets.service';
import { AssetGraphService } from './asset-graph.service';

/** Internal API — only reachable from the gateway, which supplies the principal. */
@ApiTags('assets')
@Controller('internal/assets')
export class AssetsController {
  constructor(
    private readonly assets: AssetsService,
    private readonly graph: AssetGraphService,
  ) {}

  @Get()
  @RequirePermissions('asset:read')
  list(@CurrentOrg() orgId: string, @Query(new ZodQuery(ListAssetsQuery)) query: ListAssetsQuery) {
    return this.assets.list(orgId, query);
  }

  @Get(':id')
  @RequirePermissions('asset:read')
  get(@CurrentOrg() orgId: string, @Param('id') id: string) {
    return this.assets.get(orgId, id);
  }

  @Get(':id/graph')
  @RequirePermissions('asset:read')
  neighborhood(
    @CurrentOrg() orgId: string,
    @Param('id') id: string,
    @Query('depth') depth?: string,
  ) {
    return this.graph.neighborhood(orgId, id, Number(depth ?? 2));
  }

  @Post()
  @RequirePermissions('asset:write')
  upsert(
    @CurrentOrg() orgId: string,
    @Body(new ZodBody(UpsertAssetRequest)) body: UpsertAssetRequest,
  ) {
    return this.assets.upsert(orgId, body);
  }
}
