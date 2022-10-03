import { BadRequestException, Injectable, PipeTransform } from '@nestjs/common';
import { UserStatus } from '../../common/enums/userStatus';

@Injectable()
export class TaskStatusValidationPipe implements PipeTransform {
  readonly allowedStatus = [
    UserStatus.activated,
    UserStatus.deactivated,
    UserStatus.online,
    UserStatus.offline,
    UserStatus.bloked,
  ];

  transform(value: any) {
    value = value.toUpperCase();

    if (!this.isStatusValid(value)) {
      throw new BadRequestException(
        `${value} no es un estado de usuario válido`,
      );
    }
    return value;
  }

  private isStatusValid(status: any) {
    const idx = this.allowedStatus.indexOf(status);
    return idx !== -1;
  }
}
