import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class EmailConfirmationGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const { user } = context.switchToHttp().getRequest();

    if (!user?.isEmailConfirmed) {
      throw new HttpException(
        'Confirma tu correo electrónico primero',
        HttpStatus.NOT_ACCEPTABLE,
      );
    }
    return true;
  }
}
