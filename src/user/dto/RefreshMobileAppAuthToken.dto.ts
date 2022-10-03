import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshMobileAppAuthToken {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  refreshAuthTokenMobile: string;
}
