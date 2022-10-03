import { forwardRef, Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import {
  JWT_ACCESS_TOKEN_EXPIRATION_TIME,
  SECRECT_JWT,
} from '../config/constants';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtRefreshTokenStrategy } from './strategies/jwt-refresh-token.strategy';
import { UserModule } from '../user/user.module';
import { JwtRefreshTokenStrategyMobileApp } from './strategies/jwt-refresh-token-mobile.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>(SECRECT_JWT),
        signOptions: {
          expiresIn: config.get<string>(JWT_ACCESS_TOKEN_EXPIRATION_TIME),
        },
      }),
    }),
    forwardRef(() => UserModule),
  ],
  controllers: [],
  providers: [
    AuthService,
    LocalStrategy,
    JwtStrategy,
    JwtRefreshTokenStrategy,
    JwtRefreshTokenStrategyMobileApp,
  ],
  exports: [AuthService],
})
export class AuthModule {}
