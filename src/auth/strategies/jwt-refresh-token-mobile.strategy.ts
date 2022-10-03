import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JWT_REFRESH_TOKEN_SECRET } from '../../config/constants';
import { UserService } from '../../user/user.service';
import { JwtPayload } from './jwt-payload.interface';

@Injectable()
export class JwtRefreshTokenStrategyMobileApp extends PassportStrategy(
  Strategy,
  'jwt-refresh-token-MobileApp',
) {
  constructor(
    private readonly authService: UserService,
    private readonly configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromBodyField('refreshAuthTokenMobile'),
      ignoreExpiration: true,
      secretOrKey: configService.get<string>(JWT_REFRESH_TOKEN_SECRET),
      passReqToCallback: true,
    });
  }

  async validate(req, payload: JwtPayload) {
    const user = await this.authService.getOneUserById(payload.id);
    if (!user || payload?.isApp == false) {
      throw new UnauthorizedException('Usuario no autorizado');
    }
    if (
      req.body.refreshAuthTokenMobile != user.currentHashedRefreshTokenMobile
    ) {
      throw new UnauthorizedException('Actualización no autorizada');
    }
    return user;
  }
}
