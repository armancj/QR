import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  NotAcceptableException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import { FindOptionsWhere, Like, Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { isEmail } from 'class-validator';
import { AuthService } from '../auth/auth.service';
import { StripeService } from '../stripe/stripe.service';
import { UserRole } from '../common/enums/userRole';
import { UserStatus } from '../common/enums/userStatus';
import { ChangeProfilePasswordDto } from '../auth/dto/changeProfilePassword.dto';
import { handleError } from '../common/errors/handleError';
import { CustomResult } from '../common/dto/commonResult.dto';
import { ChangePasswordDTO } from '../common/dto/changePasswordDTO.dto';
import { changeAdminPasswordDto } from './dto/change-admin-password.dto';
import { QueryUserDto } from './dto/query-user.dto';
import { MinioApiService } from '../minio-api/minio-api.service';
import { SysLogsService } from '../sys-logs/sys-logs.service';
import { LogTypeEnum } from '../sys-logs/entities/sys-log.entity';
import { SyslogInterface } from './interface/syslog.interface';
import { Subscription } from '../subscriptions/entities/subscription.entity';
import { SubscriptionStatus } from '../common/enums/subscriptionStatus.enum';
import { JwtPayload } from '../auth/strategies/jwt-payload.interface';
import * as moment from 'moment';
import { EmailDto } from '../email/dto/email.dto';
import { TemplateEnum } from '../common/enums/template.enum';
import { MobileApp } from './entities/mobile-app.entity';
import { SendPreDataForRegisterDto } from './dto/send-pre-data-for-register.dto';
import { EnTvUsaEmail } from './entities/en-tv-usa-email.entity';
import { EmailTypeEnum } from './enum/email-type.enum';
import { ChangeEmailDto } from './dto/change-email.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(EnTvUsaEmail)
    private readonly enTvUsaEmailRepository: Repository<EnTvUsaEmail>,
    @InjectRepository(MobileApp)
    private readonly mobileAppRepository: Repository<MobileApp>,
    @InjectRepository(Subscription)
    private readonly subscriptionRepository: Repository<Subscription>,
    @Inject(AuthService) private authService: AuthService,
    private readonly stripeService: StripeService,
    @Inject(MinioApiService)
    private readonly minioService: MinioApiService,
    private readonly sysLogsService: SysLogsService,
  ) {}

  async sysLogUserSave(syslogInterface: SyslogInterface): Promise<void> {
    const { req, response } = syslogInterface;
    await this.sysLogsService.registerLog(
      req,
      {
        timestamp: new Date().toISOString(),
        httpStatus: response.status,
        path: req.url,
        message: response.message,
        ip: req.ip,
        info: req.headers && req.headers.x_info,
      },
      {
        description: 'Log captured!!',
        type: LogTypeEnum.LOG,
      },
    );
  }
  //
  private async findOneUserByEmailOrUsername(
    email?: string,
    username?: string,
  ) {
    const user = await this.userRepository.findOne({
      where: [{ email }, { username }],
    });
    if (user) {
      if (user.email === email)
        throw new ConflictException(
          `El correo electrónico: ${email} existe en el sistema.`,
        );
      if (user.username === username)
        throw new ConflictException(
          `El nombre de usuario: ${username} existe en el sistema`,
        );
    }
  }

  async registerUserService(createUserDto: CreateUserDto): Promise<User> {
    const { email, name, password, lastname, code } = createUserDto;

    if (!code)
      throw new NotFoundException(
        `El código del correo electrónico no puede estar vacio. Revise su correo e intente de nuevo`,
      );

    const emailSave = await this.enTvUsaEmailRepository.findOne({
      where: { activateCode: code, type: EmailTypeEnum.register },
    });
    if (!emailSave) {
      throw new NotFoundException(
        `El código: ${code} es incorrecto del email: ${email}`,
      );
    }
    const now: Date = new Date(Date.now());
    if (now > emailSave.expireCode) {
      throw new NotAcceptableException(`El código: ${code} se ha Expirado!!`);
    }
    const user = new User();
    user.email = emailSave.email;
    user.name = emailSave.name;
    user.lastname = lastname;
    user.salt = await bcrypt.genSalt();
    user.password = await UserService.hashPassword(password, user.salt);
    user.isEmailConfirmed = true;

    const stripeCustomer = await this.stripeService.createCustomer(
      emailSave.name,
      emailSave.email,
    );
    user.stripeCustomerId = stripeCustomer.id;
    try {
      const data = await this.userRepository.save(user);
      delete data.salt;
      delete data.currentHashedRefreshToken;
      delete data.password;
      delete data.expireCode;
      delete data.activateCode;
      delete data.stripeCustomerId;
      delete data.username;
      return data;
    } catch (error) {
      handleError(error, 'correo electrónico o el nombre de usuario');
    }
  }

  private static async hashPassword(
    password: string,
    salt: string,
  ): Promise<string> {
    return bcrypt.hash(password, salt);
  }

  async findAllUsers(
    user: JwtPayload,
    queryUserDto: QueryUserDto,
  ): Promise<{ result: User[]; count: number }> {
    const { limit, offset, role, email, name } = queryUserDto;
    let emailData, nameData;
    if (email) emailData = Like(`%${queryUserDto.email}%`);
    if (name) nameData = Like(`%${queryUserDto.name}%`);
    const IsExist =
      user.role === (UserRole.administrator || UserRole.superAdmin)
        ? {
            role,
            name: nameData,
            email: emailData,
            /*username: Like(`%${username}%`),*/
          }
        : { role: user.role, status: UserStatus.activated };
    const [result, count] = await this.userRepository.findAndCount({
      where: IsExist,
      select: {
        id: true,
        username: true,
        email: true,
        name: true,
        lastname: true,
        role: true,
        status: true,
        createdAt: true,
        isEmailConfirmed: true,
      },
      skip: offset,
      take: limit,
    });
    return { result, count };
  }

  async findOneUser(id: number, user?: JwtPayload): Promise<User> {
    const dataId = user
      ? user.role !== (UserRole.administrator || UserRole.superAdmin)
        ? { id: user.id }
        : { id }
      : { id };
    const result = await this.userRepository.findOne({
      where: dataId,
      select: {
        id: true,
        username: true,
        email: true,
        name: true,
        lastname: true,
        role: true,
        status: true,
        createdAt: true,
        updateAt: true,
        isEmailConfirmed: true,
      },
    });
    if (!result) {
      throw new NotFoundException(`El usuario # ${id} no está en el sistema.`);
    }
    return result;
  }

  async findGetProfile(user: JwtPayload): Promise<User> {
    const result = await this.userRepository.findOne({
      where: { id: user.id, status: UserStatus.activated },
      select: {
        id: true,
        username: true,
        email: true,
        name: true,
        lastname: true,
        role: true,
        status: true,
        createdAt: true,
        updateAt: true,
        isEmailConfirmed: true,
        subscriptions: {
          id: true,
          status: true,
          cancel_at_period_end: true,
          cancel_at: true,
          priceToCategory: {
            id: true,
            categories: {
              id: true,
              name: true,
            },
            periods: {
              interval: true,
              interval_count: true,
              unit_amount: true,
              trial_period_days: true,
            },
          },
        },
      },
      relations: {
        subscriptions: {
          priceToCategory: {
            periods: true,
            categories: true,
          },
        },
      },
    });
    if (!result) {
      throw new NotFoundException(
        `El usuario # ${user.name} no está activado.`,
      );
    }
    result.subscriptions = result.subscriptions.filter(
      (s) => s.status == SubscriptionStatus.active,
    );
    return result;
  }

  //
  async updateUser(
    id: number,
    updateUserDto?: UpdateUserDto,
    user?: JwtPayload,
  ): Promise<User> {
    const { username, name, lastname, email, status, role } = updateUserDto;
    const dataId = user
      ? user.role !== (UserRole.administrator || UserRole.superAdmin)
        ? { id: user.id, status: UserStatus.activated }
        : { id }
      : { id };
    const dataUser =
      user.role === (UserRole.administrator || UserRole.superAdmin)
        ? { username, name, lastname, email, status, role }
        : { username, name, lastname };
    const userdata = await this.userRepository.findOne({ where: dataId });
    if (!userdata)
      throw new NotFoundException(`El usuario con # ${id} no existe`);
    if (username) await this.verifyUsername(username, userdata);
    let isEmailConfirmed: boolean;
    if (email) await this.verifyEmail(email, userdata);
    isEmailConfirmed = userdata.isEmailConfirmed;
    if (email !== userdata.email) {
      isEmailConfirmed = true;
      if (userdata.role === UserRole.online)
        try {
          await this.stripeService.stripe.customers.update(
            userdata.stripeCustomerId,
            {
              name,
              email,
            },
          );
        } catch (error) {
          handleError(error, `${error.message}`);
        }
    }
    await this.userRepository
      .update(dataId, { ...dataUser, isEmailConfirmed })
      .catch(async (error) => {
        if (error) {
          const user_data = await this.userRepository.findOne({
            where: dataId,
          });
          await this.stripeService.stripe.customers.update(
            user_data.stripeCustomerId,
            {
              name: user_data.name,
              email: user_data.email,
            },
          );
          throw new NotAcceptableException(`${error.message}`);
        }
      });
    const data = await this.userRepository.findOne({ where: dataId });
    delete data.activateCode;
    delete data.expireCode;
    delete data.salt;
    delete data.currentHashedRefreshToken;
    delete data.password;
    delete data.stripeCustomerId;
    return data;
  }

  async updateUserCard(id: number, cardCustomerId: string) {
    return this.userRepository.update(id, {
      cardCustomerId,
    });
  }

  async removeUser(user: JwtPayload): Promise<{ message: string }> {
    const findOne = await this.userRepository.findOne({
      where: { id: user.id, status: UserStatus.activated },
    });
    await this.userRepository.update(findOne.id, {
      status: UserStatus.deactivated,
      username: null,
    });
    if (findOne.role !== (UserRole.administrator || UserRole.superAdmin))
      if (findOne.subscriptions?.length)
        findOne.subscriptions.map((subscription) => {
          return this.preloadSubscription(subscription, findOne);
        });
    return { message: `Ha eliminado el usuario #${user.id} exitosamente` };
  }

  async validateUserOrEmail(email?: string, username?: string) {
    const query = this.userRepository.createQueryBuilder('user');
    query.where('user.email=:email', { email });
    query.orWhere('user.username=:username', { username });
    query.andWhere('user.status=:status', { status: UserStatus.activated });
    const user = await query.getOne();
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }

  async validateUserPassword(password: string, username: string) {
    const data = isEmail(username)
      ? { email: username, status: UserStatus.activated }
      : { username, status: UserStatus.activated };
    const user = await this.userRepository.findOne({
      where: data,
    });
    if (user && (await user.validatePassword(password))) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async setCurrentRefreshToken(refreshToken: string, user: any) {
    return this.userRepository.update(user.id, {
      currentHashedRefreshToken: refreshToken,
    });
  }

  async signIn(
    username: string,
    password: string,
    isApp?: boolean,
  ): Promise<{
    accessToken: string;
    refreshAuthToken: string;
    refreshAuthTokenMobile?: string;
  }> {
    const users = await this.validateUserPassword(password, username);
    if (!users) {
      throw new UnauthorizedException('Credenciales no válidas');
    }
    if (users.status === UserStatus.deactivated)
      throw new NotAcceptableException(
        `Este usuario con correo electrónico: ${users.email} está desactivado`,
      );

    if (users.status === UserStatus.deleted)
      throw new NotAcceptableException(
        `Este usuario con correo electrónico: ${users.email} ha sido eliminado`,
      );

    if (users.isEmailConfirmed === false)
      throw new NotAcceptableException(
        `El correo electrónico: ${users.email} no se ha confirmado. Por favor confirmelo e intente de nuevo`,
      );

    const user = await this.userRepository.findOne({ where: { id: users.id } });
    const accessToken = await this.authService.getJwtAccessToken(user);
    /*let refreshAuthToken;
    if (isApp == true) {
      const refreshAuthTokenMobile =
        await this.authService.getJwtRefreshTokenMobile(user, isApp);
      await this.setCurrentRefreshTokenMobile(
        refreshAuthTokenMobile,
        users as User,
      );
      refreshAuthToken = await this.authService.getJwtRefreshToken(user);
      await this.setCurrentRefreshToken(refreshAuthToken, users);
      return { accessToken, refreshAuthToken, refreshAuthTokenMobile };
    }*/
    const refreshAuthToken = await this.authService.getJwtRefreshToken(user);
    await this.setCurrentRefreshToken(refreshAuthToken, users);
    return { accessToken, refreshAuthToken };
  }

  async refreshAuthToken(user: User): Promise<{
    accessToken: string;
    refreshAuthToken: string;
  }> {
    const accessToken = await this.authService.getJwtAccessToken(user);
    const refreshAuthToken = await this.authService.getJwtRefreshToken(user);
    await this.setCurrentRefreshToken(refreshAuthToken, user);
    return { accessToken, refreshAuthToken };
  }

  async refreshAuthMobileToken(
    user: User,
    isApp: boolean,
  ): Promise<{
    refreshAuthToken: string;
    refreshAuthTokenMobile?: string;
  }> {
    const refreshAuthTokenMobile =
      await this.authService.getJwtRefreshTokenMobile(user, isApp);
    const refreshAuthToken = await this.authService.getJwtRefreshToken(user);
    await this.setCurrentRefreshToken(refreshAuthToken, user);
    return { refreshAuthToken, refreshAuthTokenMobile };
  }

  async updateSubscriptionStatus(
    stripeCustomerId: string,
    subscriptionStatus: string,
  ) {
    try {
      return this.userRepository.update(
        { stripeCustomerId },
        { subscriptionStatus },
      );
    } catch (err) {
      console.log(err);
    }
  }

  async changeProfilePasswordService(
    user: JwtPayload,
    changeProfilePasswordDto: ChangeProfilePasswordDto,
  ): Promise<{ message: string }> {
    const result = await this.validateUserPassword(
      changeProfilePasswordDto.oldPassword,
      user.email,
    );
    if (!result) {
      throw new BadRequestException('Contraseña incorrecta.');
    }
    if (
      changeProfilePasswordDto.password !=
      changeProfilePasswordDto.verifyPassword
    ) {
      throw new NotAcceptableException('Las contraseñas no coinciden.');
    }
    const message = await this.changePassword(
      result.id,
      changeProfilePasswordDto.password,
      result.salt,
    );

    return { message };
  }

  private async changePassword(
    userId: number,
    changePassword: string,
    salted: string,
  ): Promise<string> {
    const password = await UserService.hashPassword(changePassword, salted);
    const result = await this.userRepository.update(userId, {
      password,
    });
    if (result.affected !== 1)
      throw new NotAcceptableException(`Las contraseñas no coinciden.`);
    return `Cambiada la contraseña con éxito`;
  }

  async markEmailAsConfirmed(email: string) {
    return this.userRepository.update(
      { email },
      {
        isEmailConfirmed: true,
      },
    );
  }

  getByEmail(email: string) {
    return this.userRepository.findOne({ where: { email } });
  }
  getByEmailUser(id: number) {
    return this.userRepository.findOne({ where: { id } });
  }

  async activateAccount(
    emailUser: string,
    activateCode: number,
    user?: JwtPayload,
  ): Promise<CustomResult> {
    const custom = new CustomResult();
    custom.successfully = true;
    if (!isEmail(emailUser)) {
      custom.successfully = false;
      throw new NotAcceptableException(
        `El correo electrónico: ${emailUser} tiene un formato de correo electrónico no válido`,
      );
    }
    const userEmail = user
      ? await this.getByEmailUser(user.id)
      : await this.getByEmail(emailUser);
    if (!userEmail) {
      custom.successfully = false;
      throw new NotFoundException(
        `El correo electrónico del usuario: ${emailUser}. No encontrado`,
      );
    }
    if (userEmail.isEmailConfirmed === true) {
      custom.successfully = false;
      throw new ConflictException(
        `Correo electrónico: ${emailUser} ya está confirmado`,
      );
    }
    const now: Date = new Date(Date.now());

    if (now > userEmail.expireCode) {
      custom.successfully = false;
      throw new NotAcceptableException(
        `El código: ${activateCode} se ha Expirado!!`,
      );
    }

    const data = await this.userRepository.update(
      {
        email: emailUser,
        activateCode: activateCode,
      },
      { isEmailConfirmed: true },
    );
    if (data.affected === 0) {
      custom.successfully = false;
      throw new NotFoundException(`Código: ${activateCode} no encontrado`);
    }
    custom.message = `Correo electrónico:${emailUser} confirmado Satisfactoriamente. `;
    return custom;
  }

  async sendEmailRecovery(
    emailAddress,
  ): Promise<{ result: CustomResult; user: User; email: EmailDto }> {
    if (!isEmail(emailAddress))
      throw new NotAcceptableException(
        `La dirección de correo electrónico: ${emailAddress} tiene un formato de correo electrónico no válido`,
      );
    const result = new CustomResult();
    const user = await this.userRepository.findOne({
      where: { email: emailAddress },
    });
    if (!user) {
      result.successfully = false;
      throw new NotFoundException(
        `Usuario con correo electrónico: ${emailAddress} ¡no encontrado!`,
      );
    }
    result.successfully = true;
    result.message =
      'Enviado enlace con el código de recuperación de contraseña. Ahora tienes que revisar tu correo electrónico.';
    const code = UserService.randomInt();
    const expireAt = moment();

    expireAt.add(10, 'minute');
    await this.userRepository
      .update(user.id, {
        activateCode: code,
        expireCode: expireAt.toDate(),
      })
      .catch((r) => {
        result.successfully = false;
        result.message = r.message;
      });
    const email: EmailDto = {
      to: user.email,
      subject: 'Cambio de Contraseña',
      template: TemplateEnum.recovery_password,
      context: {
        body: `Hola ${user.name}, este es su código: ${code} para cambiar su contraseña, expira en 10 minutos. `,
      },
    };
    return { result, user, email };
  }

  async removeCurrentRefreshToken(id: number) {
    return this.userRepository.update(id, {
      currentHashedRefreshToken: null,
    });
  }

  async checkOnchangePassword(
    changeDto: ChangePasswordDTO,
  ): Promise<CustomResult> {
    const { password, code } = changeDto;
    const result = new CustomResult();
    result.successfully = true;
    const user = await this.userRepository.findOne({
      where: {
        activateCode: code,
      },
    });

    if (!user) {
      throw new NotFoundException(
        `El código: ${code} no se encuentra en el sistema.`,
      );
    }
    const now: Date = new Date(Date.now());
    if (now > user.expireCode) {
      throw new NotAcceptableException(`El código: ${code} se ha Expirado!!.`);
    }

    result.message = await this.changePassword(user.id, password, user.salt);
    if (result.successfully)
      if (user.isEmailConfirmed == false) {
        await this.markEmailAsConfirmed(user.email);
      }
    return result;
  }

  private async userDeleteStriped(user: User) {
    try {
      await this.stripeService.stripe.customers.del(user.stripeCustomerId);
    } catch (error) {
      handleError(error, `${error.message}`);
    }
  }

  async createdUserService(createUserDto: CreateUserDto) {
    const { email, username, name, password, lastname, role } = createUserDto;
    await this.findOneUserByEmailOrUsername(email, username);
    const user = new User();

    user.email = email;
    user.isEmailConfirmed = true;
    user.username = username;
    user.name = name;
    user.lastname = lastname;
    user.salt = await bcrypt.genSalt();
    user.password = await UserService.hashPassword(password, user.salt);
    user.status = UserStatus.activated;
    user.role = UserRole.administrator;

    try {
      const data = await this.userRepository.save(user);
      delete data.activateCode;
      delete data.expireCode;
      delete data.salt;
      delete data.currentHashedRefreshToken;
      delete data.password;
      delete data.stripeCustomerId;
      return data;
    } catch (error) {
      handleError(error, 'correo electrónico o nombre de usuario');
    }
  }

  private async verifyUsername(username: string, user: User) {
    if (username === user.username) return username;
    const userdata = await this.userRepository.findOne({
      where: [{ username }],
    });
    if (userdata)
      throw new ConflictException(
        `El nombre de usuario: ${username} exite en el sistema`,
      );
  }

  private async verifyEmail(email: string, user: User) {
    if (email === user.email) return email;

    const userData = await this.userRepository.findOne({
      where: [{ email }],
    });
    if (userData)
      throw new ConflictException(
        `El correo electrónico: ${email} existe en el sistema`,
      );
  }

  async updateChangePasswordByAdmin(
    id: number,
    updateUserDto: changeAdminPasswordDto,
  ): Promise<{ message: string }> {
    const userData = await this.getOneUser(id);
    const message = await this.changePassword(
      id,
      updateUserDto.newPassword,
      userData.salt,
    );
    return { message };
  }

  async getOneUser(id: number) {
    const result = await this.userRepository.findOne({
      where: { id, status: UserStatus.activated },
    });
    if (!result) {
      throw new NotFoundException(`El usuario # ${id} no está en el sistema.`);
    }
    /*if (result.role === UserRole.administrator)
      throw new UnauthorizedException(
        `No puede cambiar la contraseña a un usuario con el rol: ${UserRole.administrator}`,
      );*/

    return result;
  }

  async recoverUser(id: number, user: JwtPayload) {
    const findOne = await this.userRepository.findOne({
      where: { id },
    });
    if (!findOne) {
      throw new NotFoundException(`El usuario # ${id} no está en el sistema.`);
    }
    if (findOne.status === UserStatus.activated)
      throw new NotAcceptableException(
        `El usuario con id: #${id} ya está activado`,
      );

    if (findOne.status === UserStatus.deleted)
      throw new NotAcceptableException(
        `El usuario con id: #${id} ha sido eliminado y no se puede activar`,
      );

    const result = await this.userRepository.update(findOne.id, {
      status: UserStatus.activated,
    });
    if (result.affected === 0) {
      throw new NotFoundException(`El usuario # ${id} no está en el sistema.`);
    }
    if (user.role !== UserRole.administrator || UserRole.superAdmin)
      await this.userDeleteStriped(findOne);

    return { message: `Esto activó un usuario #${id} con éxito` };
  }

  private async preloadSubscription(
    subscription: Subscription,
    findOne: User,
  ): Promise<void> {
    await this.subscriptionRepository
      .update(
        { id: subscription.id, users: { id: findOne.id } },
        {
          status: SubscriptionStatus.canceled,
        },
      )
      .then(() =>
        this.cancelSubscriptionStriped(subscription.stripeSubscriptionId),
      );
  }

  private async cancelSubscriptionStriped(subscriptionId: string) {
    try {
      return await this.stripeService.stripe.subscriptions.del(subscriptionId, {
        invoice_now: true,
      });
    } catch (error) {
      handleError(error, `${error.message}`);
    }
  }

  async removeUserProfile(
    id: number,
    user: JwtPayload,
  ): Promise<{ message: string }> {
    const findOne = await this.userRepository.findOne({
      where: {
        id,
        status: UserStatus.activated,
      },
    });
    if (!findOne) {
      throw new NotFoundException(`El usuario # ${id} no está en el sistema`);
    }
    if (findOne.email === user.email) {
      throw new UnauthorizedException(
        `No puedes desactivar tu propio usuario.`,
      );
    }
    const result = await this.userRepository.update(findOne.id, {
      status: UserStatus.deactivated,
    });
    if (result.affected === 0) {
      throw new NotFoundException(`El usuario # ${id} no está en el sistema.`);
    }
    if (findOne.subscriptions?.length > 0)
      findOne.subscriptions.map((subscription) => {
        return this.preloadSubscription(subscription, findOne);
      });
    return { message: `Esto elimina un usuario # ${id} con éxito` };
  }

  getRepository() {
    return this.userRepository;
  }
  async findOne(options: FindOptionsWhere<User>) {
    const user = await this.userRepository.findOne({
      where: options,
    });
    if (!user) throw new BadRequestException('¡Usuario no encontrado!');
    return user;
  }

  private static randomInt(): number {
    return Math.floor(Math.random() * (90000 - 10000 + 1)) + 10000;
  }

  async confirmEmail(
    user: JwtPayload,
    emailAddress: string,
  ): Promise<{ result: CustomResult; emailData: EmailDto }> {
    const result = new CustomResult();
    const find = await this.userRepository.findOne({ where: { id: user.id } });

    result.successfully = true;
    result.message = 'Email enviado con éxito!!';
    const code = UserService.randomInt();
    const expireAt = moment();
    expireAt.add(10, 'minute');
    const emailData: EmailDto = {
      to: emailAddress,
      subject: 'Confirmación de correo Electrónico',
      template: TemplateEnum.confirmation,
      context: {
        body: `Hola ${user.name}, este es su código: ${code} para confirmar su correo, expira en 10 minutos. `,
      },
    };

    await this.userRepository
      .update(user.id, {
        activateCode: code,
        email: emailAddress,
        expireCode: expireAt.toDate(),
      })
      .then(async () => {
        find.activateCode = code;
        find.email = emailAddress;
        return UserService.registerEmail(find);
      })
      .catch(() => {
        throw new ConflictException(`El email ${emailAddress} esta duplicado`);
      });
    return { result, emailData };
  }

  private static registerEmail(user: User): EmailDto {
    const contex = {
      body: 'string',
    };

    contex.body = `Estimado(a) ${user.name}, hemos recibido un registro en nuestro sistema,
      si no ha sido ud simplemente ignore este mensaje, de lo contrario este es su código de activación: ${user.activateCode}.
      Gracias por acceder a EnTvUsa!!`;

    return {
      to: user.email,
      subject: 'Confirmación de Registro, EnTvUsa',
      template: TemplateEnum.confirmation,
      context: contex,
    };
  }

  private async setCurrentRefreshTokenMobile(
    refreshAuthToken: string,
    users: User,
  ) {
    return this.userRepository.update(users.id, {
      currentHashedRefreshTokenMobile: refreshAuthToken,
    });
  }

  async removeMobileApp(user: JwtPayload) {
    const findOne = await this.userRepository.findOne({
      where: { id: user.id, status: UserStatus.activated },
    });
    await this.userRepository.update(findOne.id, {
      status: UserStatus.deleted,
      email: `DELETED_old-${user.id}-${user.email}`,
    });
    if (findOne.role !== UserRole.administrator || UserRole.superAdmin)
      if (findOne.subscriptions?.length)
        findOne.subscriptions.map((subscription) => {
          return this.preloadSubscription(subscription, findOne);
        });
    return { message: `Ha eliminado el usuario #${user.id} exitosamente` };
  }

  async preRegisterService(dto: SendPreDataForRegisterDto) {
    const exist = await this.userRepository.findOne({
      where: {
        email: dto.email,
      },
    });
    if (exist)
      throw new BadRequestException(
        `El correo electrónico: ${dto.email} ya esta en uso!!`,
      );
    const code = UserService.randomInt();
    const expireAt = moment();
    expireAt.add(10, 'minute');
    const result = await this.enTvUsaEmailRepository.findOne({
      where: { email: dto.email, type: EmailTypeEnum.register },
    });
    const data: EmailDto = {
      to: dto.email,
      subject: 'Register Email',
      template: TemplateEnum.pre_register,
      context: {
        body: `Estimado(a) ${dto.name}, hemos recibido un registro en nuestro sistema,
      si no ha sido ud simplemente ignore este mensaje, de lo contrario este es su código de activación: ${code} expira en 10 minutos.
      Gracias por acceder a EnTvUsa!!`,
      },
    };

    if (result) {
      await this.enTvUsaEmailRepository.update(
        { email: result.email, type: EmailTypeEnum.register },
        {
          expireCode: expireAt.toDate(),
          activateCode: code,
          name: dto.name,
        },
      );
      return data;
    }
    const enTvUsaEmail = new EnTvUsaEmail();
    enTvUsaEmail.activateCode = code;
    enTvUsaEmail.expireCode = expireAt.toDate();
    enTvUsaEmail.email = dto.email;
    enTvUsaEmail.type = EmailTypeEnum.register;
    enTvUsaEmail.name = dto.name;
    await this.enTvUsaEmailRepository.save(enTvUsaEmail);
    return data;
  }

  async changeEmailService(user: JwtPayload, changeEmailDto: ChangeEmailDto) {
    const exist = await this.userRepository.findOne({
      where: {
        email: changeEmailDto.email,
      },
    });

    if (exist) {
      if (exist.email === changeEmailDto.email && exist.id === user.id) {
        throw new NotAcceptableException(
          `El correo electrónico: ${changeEmailDto.email} no lo necesitas cambiar ya que es el que tiene en uso actualmente`,
        );
      }
      throw new BadRequestException(
        `El correo electrónico: ${changeEmailDto.email} ya esta en uso!!`,
      );
    }
    const code = UserService.randomInt();
    const expireAt = moment();
    expireAt.add(10, 'minute');
    const result = await this.enTvUsaEmailRepository.findOne({
      where: { email: changeEmailDto.email, type: EmailTypeEnum.updated },
    });
    const data: EmailDto = {
      to: changeEmailDto.email,
      subject: 'Confirmación de cambio de correo electrónico',
      template: TemplateEnum.confirmation,
      context: {
        body: `Hola ${user.name}, hemos recibido un cambio de email en nuestro sistema.
      Este es su código de activación: ${code}. Expira en 10 minutos.
      Gracias por acceder a EnTvUsa!!`,
      },
    };
    if (result) {
      await this.enTvUsaEmailRepository.update(
        { email: changeEmailDto.email, type: EmailTypeEnum.updated },
        {
          expireCode: expireAt.toDate(),
          activateCode: code,
          name: user.name,
        },
      );
      return data;
    }
    const enTvUsaEmail = new EnTvUsaEmail();
    enTvUsaEmail.activateCode = code;
    enTvUsaEmail.expireCode = expireAt.toDate();
    enTvUsaEmail.email = changeEmailDto.email;
    enTvUsaEmail.type = EmailTypeEnum.updated;
    enTvUsaEmail.name = user.name;
    await this.enTvUsaEmailRepository.save(enTvUsaEmail);
    return data;
  }

  async updatedEmailUserService(
    user: JwtPayload,
    code: number,
  ): Promise<{ message: string }> {
    if (!code)
      throw new NotFoundException(
        `El código del correo electrónico no puede estar vacio. Revise su correo e intente de nuevo`,
      );

    const emailSave = await this.enTvUsaEmailRepository.findOne({
      where: { activateCode: code, type: EmailTypeEnum.updated },
    });
    if (!emailSave) {
      throw new NotFoundException(`El código: ${code} es incorrecto`);
    }
    const now: Date = new Date(Date.now());
    if (now > emailSave.expireCode) {
      throw new NotAcceptableException(`El código: ${code} se ha Expirado!!`);
    }
    const data = await this.userRepository.update(user.id, {
      email: emailSave.email,
      isEmailConfirmed: true,
    });
    if (!data)
      throw new NotFoundException(
        `No se ha podido actualizar el correo electrónico`,
      );
    return { message: 'Se ha actualizado el correo electrónico con éxito' };
  }

  async getOneUserById(id: number) {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
