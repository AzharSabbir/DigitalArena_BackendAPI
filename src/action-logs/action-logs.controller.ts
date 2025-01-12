import {
  Body,
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Req,
  ValidationPipe,
} from '@nestjs/common';
import { ActionLogsService } from './action-logs.service';
import { Role } from 'src/auth/enums/role.enum';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { CreateActionLogDto } from './dto/create-action-log.dto';
import { Public } from 'src/auth/decorators/public.decorator';

@Controller('action-logs')
export class ActionLogsController {
  constructor(private actionLogsService: ActionLogsService) {}

  /////////////////////////////// GET All Action Logs ///////////////////////////////
  // @Roles(Role.ADMIN)
  @Public()
  @Get('getAllActionLogs')
  async getAllActionLogs() {
    return this.actionLogsService.getAllActionLogs();
  }

  /////////////////////////////// GET Specific User Action Logs ///////////////////////////////
  @Roles(Role.ADMIN)
  @Get('getUserActionLogs/:userId')
  async getUserActionLogs(@Param('userId', ParseIntPipe) userId: number) {
    return this.actionLogsService.getUserActionLogs(userId);
  }

  /////////////////////////////// CREATE Action Log(Authorized User) ///////////////////////////////
  @Post('createAuthorizedActionLog')
  async createAuthorizedActionLog(
    @Req() req: any,
    @Body(ValidationPipe) createActionLogDto: CreateActionLogDto,
  ) {
    createActionLogDto.user = req.user;
    return this.actionLogsService.createActionLog(createActionLogDto);
  }

  /////////////////////////////// CREATE Action Log(unAuthorized User/Guest User) ///////////////////////////////
  @Public()
  @Post('createUnauthorizedActionLog')
  async createUnauthorizedActionLog(
    @Body(ValidationPipe) createActionLogDto: CreateActionLogDto,
  ) {
    createActionLogDto.user = null;
    return this.actionLogsService.createActionLog(createActionLogDto);
  }
}
