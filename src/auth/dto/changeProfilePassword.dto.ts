import { IsNotEmpty, Length, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangeProfilePasswordDto {
  @ApiProperty()
  @IsNotEmpty({
    message: 'El campo no puede estar en blanco.',
  })
  @Length(8, 15, {
    message:
      'La contraseña debe tener una longitud mínima de 8 caracteres y una longitud máxima de 15 caracteres.',
  })
  readonly oldPassword: string;

  @ApiProperty()
  @IsNotEmpty({
    message: 'El campo no puede estar en blanco.',
  })
  @Length(8, 15, {
    message:
      'La contraseña debe tener una longitud mínima de 8 caracteres y una longitud máxima de 15 caracteres.',
  })
  @Matches(/(?:(?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Contraseña demasiado débil',
  })
  readonly password: string;

  @ApiProperty()
  @IsNotEmpty({
    message: 'El campo no puede estar en blanco.',
  })
  @Length(8, 15, {
    message:
      'La contraseña debe tener una longitud mínima de 8 caracteres y una longitud máxima de 15 caracteres.',
  })
  @Matches(/(?:(?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Contraseña demasiado débil',
  })
  readonly verifyPassword: string;
}
