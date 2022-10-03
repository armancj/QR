import {
  Body,
  Controller,
  Delete,
  Get,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  Res,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CreateSettingDto } from './dto/create-setting.dto';
import { UpdateSettingDto } from './dto/update-setting.dto';
import { SettingService } from './setting.service';
import { Auth } from '../common/decorators/api-swagger-consumer.decorator';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../common/enums/userRole';

@ApiTags('Setting')
@Controller('setting')
export class SettingController {
  constructor(private readonly settingService: SettingService) {}

  @Auth()
  @Roles(UserRole.superAdmin)
  @Get('list')
  async list(@Res() res) {
    const list = await this.settingService.getSetting();
    return res.status(HttpStatus.OK).json(list);
  }

  @Auth()
  @Roles(UserRole.superAdmin)
  @Get('listServer')
  async listEnvServer(@Res() res) {
    const list = await this.settingService.getSettingEnv();
    return res.status(HttpStatus.OK).json(list);
  }

  @Auth()
  @Roles(UserRole.superAdmin)
  @Post('create')
  async create(@Res() res, @Body() dto: CreateSettingDto) {
    const created = await this.settingService.createVar(dto);
    return res.status(HttpStatus.CREATED).json(created);
  }

  @Auth()
  @Roles(UserRole.superAdmin)
  @Put('update/:uuid')
  async update(
    @Res() res,
    @Param('uuid', ParseUUIDPipe) uuid: string,
    @Body() dto: UpdateSettingDto,
  ) {
    const updated = await this.settingService.updateVar(uuid, dto);
    return res.status(HttpStatus.OK).json(updated);
  }

  @Auth()
  @Roles(UserRole.superAdmin)
  @Delete('delete/:uuid')
  async delete(@Res() res, @Param('uuid', ParseUUIDPipe) uuid: string) {
    const updated = await this.settingService.deleteVar(uuid);
    return res.status(HttpStatus.OK).json(updated);
  }

  @Auth()
  @Roles(UserRole.superAdmin)
  @Get('listPublic')
  async listPublic(@Res() res) {
    const list = await this.settingService.getPublicVars();
    return res.status(HttpStatus.OK).json(list);
  }
}
