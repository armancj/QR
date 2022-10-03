import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { UserStatus } from '../../common/enums/userStatus';

@Injectable()
export class UserDeactivatedGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const { user } = context.switchToHttp().getRequest();

    if (user?.status === UserStatus.deactivated) {
      throw new HttpException(
        'Su usuario no está activado. Activa tu cuenta y prueba',
        HttpStatus.UNAUTHORIZED,
      );
    }
    if (user?.status === UserStatus.deleted) {
      throw new HttpException(
        'Su usuario no está autorizado',
        HttpStatus.UNAUTHORIZED,
      );
    }
    return true;
  }
}
