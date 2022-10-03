import {
  IsBoolean,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export class UpdateSettingDto {
  @IsOptional()
  @MinLength(3)
  @IsString()
  name?: string;

  @IsOptional()
  value?: string;

  @IsOptional()
  @MinLength(3)
  @IsString()
  description?: string;

  //@IsOptional()
  @IsNotEmpty()
  @IsBoolean()
  active: boolean;

  @IsOptional()
  @IsNotEmpty()
  @IsBoolean()
  isPublic: boolean;
}
