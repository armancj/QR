import { IntersectionType } from '@nestjs/swagger';
import { GetStatusFilterDto } from './get-status-filter.dto';
import { PaginationQueryDto } from '../../common/dto/pagination-query.dto';

export class QueryUserDto extends IntersectionType(
  GetStatusFilterDto,
  PaginationQueryDto,
) {}
