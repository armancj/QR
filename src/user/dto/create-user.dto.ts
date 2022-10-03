import { UserRole } from '../../common/enums/userRole';
import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class CreateUserDto {
  @ApiProperty()
  @IsOptional()
  @IsString()
  @MaxLength(128)
  name: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  @MaxLength(255)
  lastname: string;

  @ApiProperty()
  @IsString()
  @IsOptional()
  @MaxLength(64)
  username: string;

  @ApiProperty()
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsOptional()
  @IsInt()
  code: number;

  @ApiProperty()
  @IsString()
  @MinLength(8)
  @MaxLength(15)
  @Matches(/(?:(?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Contraseña demasiado débil',
  })
  password: string;

  @ApiProperty({
    enum: [UserRole.online, UserRole.administrator],
    description: `${UserRole.online} or ${UserRole.administrator}`,
  })
  @IsOptional()
  @IsEnum(UserRole, {
    message: `The Roles are ${UserRole.online} or ${UserRole.administrator} `,
  })
  role: UserRole;
}
