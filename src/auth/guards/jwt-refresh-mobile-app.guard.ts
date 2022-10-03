import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export default class JwtRefreshMobileAppGuard extends AuthGuard(
  'jwt-refresh-token-MobileApp',
) {}
