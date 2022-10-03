import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './strategies/jwt-payload.interface';
import { ConfigService } from '@nestjs/config';
import {
  JWT_REFRESH_TOKEN_EXPIRATION_TIME,
  JWT_REFRESH_TOKEN_SECRET,
} from '../config/constants';
import { User } from '../user/entities/user.entity';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('AuthService');
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async getJwtAccessToken(user: JwtPayload, isApp?: boolean): Promise<string> {
    const {
      id,
      email,
      username,
      name,
      lastname,
      role,
      status,
      stripeCustomerId,
      isEmailConfirmed,
    } = user;
    const payload: JwtPayload = {
      id,
      email,
      username,
      name,
      lastname,
      isEmailConfirmed,
      role,
      status,
      stripeCustomerId,
      isApp,
    };
    const accessToken = this.jwtService.sign(payload);
    this.logger.debug(
      `Generate JWT Token with payload ${JSON.stringify(payload)}`,
    );
    return accessToken;
  }

  async getJwtRefreshToken(user: User): Promise<string> {
    const payload = {
      id: user.id,
      username: user.username,
      email: user.email,
      rol: user.role,
      isEmailConfirmed: user.isEmailConfirmed,
    };
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>(JWT_REFRESH_TOKEN_SECRET),
      expiresIn: this.configService.get(JWT_REFRESH_TOKEN_EXPIRATION_TIME),
    });
    this.logger.debug(
      `Generate JWT Token refresh with payload ${JSON.stringify(payload)}`,
    );
    return refreshToken;
  }

  async getJwtRefreshTokenMobile(user: JwtPayload, isApp: boolean) {
    const payload = {
      id: user.id,
      username: user.username,
      email: user.email,
      rol: user.role,
      isApp,
    };

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>(JWT_REFRESH_TOKEN_SECRET),
      expiresIn: this.configService.get(JWT_REFRESH_TOKEN_EXPIRATION_TIME),
    });
    this.logger.debug(
      `Generate JWT Token refresh with payload ${JSON.stringify(payload)}`,
    );
    return refreshToken;
  }
}
