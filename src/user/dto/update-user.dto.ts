import { OmitType, PartialType } from '@nestjs/swagger';
import { CreateUserDto } from './create-user.dto';
import { IsEnum, IsOptional } from 'class-validator';
import { UserStatus } from '../../common/enums/userStatus';
export class UpdateUserDto extends PartialType(
  OmitType(CreateUserDto, ['password'] as const),
) {
  @IsOptional()
  @IsEnum(UserStatus, {
    message: `Los estados son ${UserStatus.activated}, ${UserStatus.online}, ${UserStatus.bloked}, ${UserStatus.offline},  ${UserStatus.deactivated}`,
  })
  status: UserStatus;
}
