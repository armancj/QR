import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsOptional, IsString, MaxLength } from 'class-validator';

export class SendPreDataForRegisterDto {
  @ApiProperty()
  @IsOptional()
  @IsString()
  @MaxLength(128)
  name: string;

  @ApiProperty()
  @IsEmail()
  email: string;
}
