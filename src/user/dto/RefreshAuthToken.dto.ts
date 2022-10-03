import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshAuthTokenDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  refreshAuthToken: string;
}
