import { Body, Controller, Get, Param, Post, Query, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '@ctem/auth';
import type { Asset, ListAssetsQuery, UpsertAssetRequest } from '@ctem/contracts';
import { ServiceProxy } from '../proxy/service-proxy';

@ApiTags('assets')
@ApiBearerAuth()
@Controller('v1/assets')
export class AssetsProxyController {
  constructor(private readonly proxy: ServiceProxy) {}

  @Get()
  @RequirePermissions('asset:read')
  list(@Req() req: never, @Query() query: ListAssetsQuery) {
    return this.proxy.forward('asset', 'GET', '/internal/assets', req, { query });
  }

  @Get(':id')
  @RequirePermissions('asset:read')
  get(@Req() req: never, @Param('id') id: string) {
    return this.proxy.forward<Asset>('asset', 'GET', `/internal/assets/${id}`, req);
  }

  @Get(':id/graph')
  @RequirePermissions('asset:read')
  graph(@Req() req: never, @Param('id') id: string, @Query('depth') depth = '2') {
    return this.proxy.forward('asset', 'GET', `/internal/assets/${id}/graph`, req, {
      query: { depth },
    });
  }

  @Post('discover')
  @RequirePermissions('integration:manage')
  discover(@Req() req: never) {
    return this.proxy.forward('asset', 'POST', '/internal/assets/discover', req);
  }

  @Post()
  @RequirePermissions('asset:write')
  upsert(@Req() req: never, @Body() body: UpsertAssetRequest) {
    return this.proxy.forward<Asset>('asset', 'POST', '/internal/assets', req, { body });
  }
}
