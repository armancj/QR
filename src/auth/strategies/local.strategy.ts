import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthValidateDto } from '../dto/auth-validate.dto';
import { UserService } from '../../user/user.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: UserService) {
    super();
  }

  async validate(authCredentialsDto: AuthValidateDto): Promise<any> {
    const user = await this.authService.validateUserPassword(
      authCredentialsDto.password,
      authCredentialsDto.username,
    );
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
