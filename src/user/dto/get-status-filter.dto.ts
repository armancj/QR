import { IsIn, IsOptional, IsString } from 'class-validator';
import { UserRole } from '../../common/enums/userRole';
import { ApiProperty } from '@nestjs/swagger';

export class GetStatusFilterDto {
  @ApiProperty({ enum: UserRole })
  @IsOptional()
  @IsIn([UserRole.online, UserRole.administrator, UserRole.superAdmin])
  role: UserRole;

  @ApiProperty()
  @IsOptional()
  @IsString()
  name?: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  email?: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  username?: string;
}
