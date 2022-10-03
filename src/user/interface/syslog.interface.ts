import { LogTypeEnum } from '../../sys-logs/entities/sys-log.entity';
import { Request } from 'express';

export interface SyslogInterface {
  req: Request;
  response: any;
  description: string;
  type?: LogTypeEnum;
  subscriptionId?: number;
  pricesId?: number;
  categoriesId?: number;
  videosId?: number;
  cardCreditsId?: number;
}
