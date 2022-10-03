import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, Length, Matches } from 'class-validator';

export class changeAdminPasswordDto {
  @ApiProperty()
  @IsNotEmpty()
  @Length(8, 15)
  @Matches(/(?:(?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Contraseña demasiado débil',
  })
  readonly newPassword: string;
}
