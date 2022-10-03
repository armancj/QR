import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class AuthValidateDto {
  @ApiProperty({ type: 'string' })
  @IsString()
  readonly username: string;

  @ApiProperty()
  @IsString()
  readonly password: string;

  /*@ApiProperty()
  @IsOptional()
  @IsBoolean()
  readonly isApp: boolean;*/
}
