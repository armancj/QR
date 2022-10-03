import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpStatus,
  Param,
  ParseIntPipe,
  Patch,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiPreconditionFailedResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { AuthValidateDto } from '../auth/dto/auth-validate.dto';
import { User } from './entities/user.entity';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ChangeProfilePasswordDto } from '../auth/dto/changeProfilePassword.dto';
import { RefreshAuthTokenDto } from './dto/RefreshAuthToken.dto';
import { Roles } from '../auth/decorators/roles.decorator';
import { changeAdminPasswordDto } from './dto/change-admin-password.dto';
import { QueryUserDto } from './dto/query-user.dto';
import JwtRefreshGuard from '../auth/guards/jwt-refresh.guard';
import { JwtPayload } from '../auth/strategies/jwt-payload.interface';
import { UserDeactivatedGuard } from '../auth/guards/user-deactivated.guard';
import { SendPreDataForRegisterDto } from './dto/send-pre-data-for-register.dto';
import { ChangeEmailDto } from './dto/change-email.dto';
import { Auth } from '../auth/decorators/api-swagger-consumer.decorator';

@ApiTags('user')
@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
  ) {}

  @Post()
  @Auth()
  @Roles(UserRole.administrator, UserRole.superAdmin)
  @ApiCreatedResponse({
    description: 'The create user has been successfully created.',
  })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  @ApiOperation({ summary: 'Create USER for Administrator' })
  @ApiBadRequestResponse({ description: 'Data pre-validation failed' })
  @ApiBody({ type: CreateUserDto })
  async createUserAdmin(@Body() createUserDto: CreateUserDto, @Req() req) {
    const user = await this.userService.createdUserService(createUserDto);
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `Create USER for Administrator`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return user;
  }

  @Post('RegisterUser')
  @ApiCreatedResponse({
    description: 'The register has been successfully created.',
  })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  @ApiOperation({ summary: 'Register USER' })
  @ApiBadRequestResponse({ description: 'Data pre-validation failed' })
  @ApiBody({ type: CreateUserDto })
  async registerUser(@Body() createUserDto: CreateUserDto) {
    return await this.userService
      .registerUserService(createUserDto)
      .then(async (user) => {
        const email: EmailDto = {
          to: user.email,
          subject: 'Bienvenido a EnTvUsa!!',
          template: TemplateEnum.welcome,
          context: {
            body: `Bienvenido ${user.name}.
              Gracias por acceder a EnTvUsa!!`,
          },
        };
        await this.emailConfirmationService.sendVerificationLink(email);
        return user;
      })
      .catch((e) => {
        throw new BadRequestException(e.message);
      });
  }

  @Post('pre-RegisterUser')
  @ApiCreatedResponse({
    description: 'The pre-register has been successfully created.',
  })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  @ApiOperation({ summary: 'Register USER' })
  @ApiBadRequestResponse({ description: 'Data pre-validation failed' })
  @ApiBody({ type: SendPreDataForRegisterDto })
  async preRegister(
    @Body() sendPreDataForRegisterDto: SendPreDataForRegisterDto,
  ) {
    return await this.userService
      .preRegisterService(sendPreDataForRegisterDto)
      .then(async (data) => {
        await this.emailConfirmationService.sendVerificationLink(data);
        return {
          message:
            'La Verificación del email se ha enviado correctamente. Por favor revise su correo',
        };
      })
      .catch((e) => {
        throw new BadRequestException(e.message);
      });
  }

  @Post('/login')
  @ApiOperation({ summary: 'Login USER' })
  @ApiOkResponse({ description: 'Return Access Token' })
  @ApiCreatedResponse({
    description: 'The user has been successfully login.',
  })
  @ApiBadRequestResponse({ description: 'Data pre-validation failed' })
  @ApiUnauthorizedResponse({ description: 'Wrong Credentials' })
  async signIn(
    @Body() authValidateDto: AuthValidateDto,
  ): Promise<{ accessToken: string; refreshAuthToken: string }> {
    const { username, password } = authValidateDto;
    return this.userService.signIn(username, password);
  }

  @Post('refresh')
  @UseGuards(JwtRefreshGuard)
  @ApiOperation({ summary: 'Return new access Token' })
  @ApiCreatedResponse({
    description: 'Data pre-validation has been successfully.',
  })
  @ApiBody({ type: RefreshAuthTokenDto })
  @ApiBadRequestResponse({ description: 'Data pre-validation failed' })
  @ApiOkResponse({ description: 'Return new access_token' })
  @ApiUnauthorizedResponse({ description: 'Invalid Token' })
  async refresh(@GetUser() user: User) {
    return this.userService.refreshAuthToken(user);
  }

  @Get()
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, UserDeactivatedGuard)
  @ApiOperation({ summary: 'Return List all users' })
  @ApiOkResponse({ description: 'List all users' })
  async findAll(
    @Query() queryUserDto: QueryUserDto,
    @GetUser() user: JwtPayload,
  ) {
    return this.userService.findAllUsers(user, queryUserDto);
  }

  @Get('logout')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Log OUT' })
  @ApiUnauthorizedResponse({ description: 'Invalid Token' })
  @ApiOkResponse({ description: 'Successfully Log out' })
  async logout(@GetUser() user: JwtPayload, @Res() res) {
    const log = await this.userService.removeCurrentRefreshToken(user.id);
    if (log)
      return res
        .status(HttpStatus.OK)
        .json({ message: 'Cerrar sesión con éxito' });
    return res
      .status(HttpStatus.NOT_FOUND)
      .json({ message: '¡Usuario no encontrado!' });
  }

  @Get('profileUserClient')
  @UseGuards(JwtAuthGuard, UserDeactivatedGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Return one users' })
  @ApiOkResponse({ description: 'Return user profile' })
  @ApiNotFoundResponse({ description: `Return user profile` })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  async profileUserClient(@GetUser() user: JwtPayload, @Res() res) {
    const usr = await this.userService.findGetProfile(user);
    return res.status(HttpStatus.OK).json(usr);
  }

  //-----Activate Email Address
  @UseGuards(JwtAuthGuard, UserDeactivatedGuard)
  @ApiOperation({ summary: 'Activate email User Account' })
  @ApiOkResponse({ type: CustomResult })
  @ApiBadRequestResponse({ description: 'User not Activated' })
  @ApiBadRequestResponse({ type: CustomResult })
  @ApiParam({ name: 'activateCode' })
  @Get('/emailUserActivated/:activateCode')
  async activateUserWithAuth(
    @Param('activateCode', ParseIntPipe) activateCode: number,
    @Res() res,
    @GetUser() user: JwtPayload,
  ): Promise<CustomResult> {
    const result = await this.userService.activateAccount(
      user.email,
      activateCode,
      user,
    );
    if (!result.successfully)
      return res.status(HttpStatus.BAD_REQUEST).json(result);

    return res.status(HttpStatus.OK).json(result);
  }

  @ApiOperation({ summary: 'Activate email User Account' })
  @ApiOkResponse({ type: CustomResult })
  @ApiBadRequestResponse({ description: 'User not Activated' })
  @ApiBadRequestResponse({ type: CustomResult })
  @ApiParam({ name: 'emailUser' })
  @ApiParam({ name: 'activateCode' })
  @Get('/emailUserActivated/:emailUser/:activateCode')
  async activateUser(
    @Param('emailUser') emailUser: string,
    @Param('activateCode', ParseIntPipe) activateCode: number,
    @Res() res,
  ): Promise<CustomResult> {
    const result = await this.userService.activateAccount(
      emailUser,
      activateCode,
    );
    if (!result.successfully)
      return res.status(HttpStatus.BAD_REQUEST).json(result);

    return res.status(HttpStatus.OK).json(result);
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiParam({ name: 'id', description: 'users id' })
  @ApiOperation({ summary: 'Return one users' })
  @ApiOkResponse({ description: ' Return user by id' })
  @ApiNotFoundResponse({ description: `id user not exist` })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  findOne(@Param('id', ParseIntPipe) id: number, @GetUser() user: JwtPayload) {
    return this.userService.findOneUser(id, user);
  }

  @ApiOperation({ summary: 'Request the code for change password' })
  @ApiParam({ name: 'email' })
  @Get('/forgot/:email')
  async requestChangePassword(
    @Res() res,
    @Req() req,
    @Param('email') emailAddress,
  ): Promise<CustomResult> {
    const data = await this.userService.sendEmailRecovery(emailAddress);

    await this.emailConfirmationService
      .sendVerificationLink(data.email)
      .catch((r) => {
        data.result.successfully = false;
        data.result.message = r.message;
      });
    if (data.result.successfully) {
      try {
        await this.userService.sysLogUserSave({
          req,
          response: {
            status: HttpStatus.CREATED,
            message: `Request the code Token for change password`,
          },
          description: 'Log captured!!',
        });
      } catch (error) {
        console.log(error);
      }
      return res.status(HttpStatus.OK).json(data.result);
    }
    return res.status(HttpStatus.BAD_REQUEST).json(data.result);
  }

  @ApiOperation({ summary: 'Change password by email code' })
  @ApiOkResponse({ description: 'Password changed Successfully' })
  @ApiBadRequestResponse({ description: 'Invalid Data' })
  @ApiBody({ type: ChangePasswordDTO })
  @Patch('recovery-password')
  async changePassword(
    @Res() res,
    @Body() change: ChangePasswordDTO,
    @Req() req,
  ): Promise<CustomResult> {
    const result = await this.userService.checkOnchangePassword(change);
    if (result.successfully) {
      try {
        await this.userService.sysLogUserSave({
          req,
          response: {
            status: HttpStatus.CREATED,
            message: `Change password by email code`,
          },
          description: 'Log captured!!',
        });
      } catch (error) {
        console.log(error);
      }
      return res.status(HttpStatus.OK).json(result);
    }
    return res.status(HttpStatus.BAD_REQUEST).json(result);
  }

  @Patch('editUserProfile/:id')
  @Roles(UserRole.administrator, UserRole.superAdmin)
  @UseGuards(JwtAuthGuard, UserDeactivatedGuard)
  @ApiBearerAuth()
  @ApiOkResponse({ description: 'Return update user successfully by id' })
  @ApiOperation({ summary: 'Update user' })
  @ApiCreatedResponse({
    description: 'The profile has been successfully updated.',
  })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  async editUserProfile(
    @Param('id', ParseIntPipe) id: number,
    @GetUser() user: JwtPayload,
    @Body() updateUserDto: UpdateUserDto,
    @Req() req,
  ) {
    const userData = await this.userService.updateUser(id, updateUserDto, user);
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `Return update user successfully by id`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return userData;
  }

  @Patch('changePasswordAdmin/:id')
  @Auth()
  @UseGuards(JwtAuthGuard, UserDeactivatedGuard)
  @ApiBearerAuth()
  @ApiOkResponse({
    description: 'Return change password user successfully by admin with id',
  })
  @ApiOperation({ summary: 'Update user' })
  @ApiCreatedResponse({
    description: 'The profile has been successfully updated.',
  })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  async changePasswordAdmin(
    @Param('id', ParseIntPipe) id: number,
    @Res() res,
    @Req() req,
    @Body() updateUserDto: changeAdminPasswordDto,
  ) {
    const result = await this.userService.updateChangePasswordByAdmin(
      id,
      updateUserDto,
    );
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `Return change password user successfully by admin with id`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return res.status(HttpStatus.OK).json(result);
  }

  @Patch('/changeProfilePassword')
  @UseGuards(JwtAuthGuard, UserDeactivatedGuard)
  @ApiBearerAuth()
  @ApiBody({ type: ChangeProfilePasswordDto })
  @ApiOperation({ summary: 'Change profile Password User' })
  @ApiOkResponse({ description: `Change password successfully` })
  @ApiForbiddenResponse({ description: `Forbidden.` })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiNotAcceptableResponse({ description: `Passwords do not match.` })
  @ApiPreconditionFailedResponse({ description: `Passwords do not match ` })
  async changeProfilePassword(
    @Res() res,
    @Req() req,
    @GetUser() user: JwtPayload,
    @Body() changeProfilePasswordDto: ChangeProfilePasswordDto,
  ) {
    const result = await this.userService.changeProfilePasswordService(
      user,
      changeProfilePasswordDto,
    );
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `Return change password user successfully`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return res.status(HttpStatus.OK).json(result);
  }

  @Patch('/changeEmail')
  @UseGuards(JwtAuthGuard, UserDeactivatedGuard)
  @ApiBearerAuth()
  @ApiBody({ type: ChangeEmailDto })
  @ApiOperation({ summary: 'Change email User' })
  @ApiOkResponse({ description: `Change email successfully` })
  @ApiForbiddenResponse({ description: `Forbidden.` })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  async changeEmail(
    @Res() res,
    @Req() req,
    @GetUser() user: JwtPayload,
    @Body() changeEmailDto: ChangeEmailDto,
  ) {
    const result = await this.userService
      .changeEmailService(user, changeEmailDto)
      .then(async (data) => {
        await this.emailConfirmationService.sendVerificationLink(data);
        return {
          message:
            'La Verificación del email se ha enviado correctamente. Por favor revise su correo',
        };
      })
      .catch((e) => {
        throw new BadRequestException(e.message);
      });
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `Return send change email user successfully`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return res.status(HttpStatus.OK).json(result);
  }

  @Patch('/changeEmail/:code')
  @Auth()
  @ApiBearerAuth()
  @ApiOkResponse({
    description: ' Return Activate email change successfully by code',
  })
  @ApiOperation({ summary: 'Activate email user' })
  @ApiCreatedResponse({
    description: 'The user has been successfully activated.',
  })
  @ApiNotFoundResponse({ description: `id user not exist` })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  async changeEmailCodeVerification(
    @Param('code', ParseIntPipe) code: number,
    @Res() res,
    @Req() req,
    @GetUser() user: JwtPayload,
  ) {
    const result = await this.userService
      .updatedEmailUserService(user, code)
      .catch((e) => {
        throw new BadRequestException(e.message);
      });
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `Return change email verification user successfully`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return res.status(HttpStatus.OK).json(result);
  }

  @Patch('activateUser/:id')
  @Auth()
  @Roles(UserRole.administrator, UserRole.superAdmin)
  @ApiBearerAuth()
  @ApiOkResponse({ description: ' Return Activate user successfully by id' })
  @ApiOperation({ summary: 'Activate user' })
  @ApiCreatedResponse({
    description: 'The user has been successfully activated.',
  })
  @ApiNotFoundResponse({ description: `id user  not exist` })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  async activate(
    @Param('id', ParseIntPipe) id: number,
    @Res() res,
    @Req() req,
    @GetUser() user: JwtPayload,
  ) {
    const result = await this.userService.recoverUser(id, user);
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `The user has been successfully activated.`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return res.status(HttpStatus.OK).json(result);
  }

  @Patch('deactivateUser/:id')
  @Auth()
  @Roles(UserRole.administrator, UserRole.superAdmin)
  @ApiBearerAuth()
  @ApiOkResponse({ description: ' Return Deactivate user successfully by id' })
  @ApiOperation({ summary: 'Deactivate user' })
  @ApiCreatedResponse({
    description: 'The user has been successfully deactivated.',
  })
  @ApiNotFoundResponse({ description: `id user not exist` })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  async deactivate(
    @Param('id', ParseIntPipe) id: number,
    @Res() res,
    @Req() req,
    @GetUser() user: JwtPayload,
  ) {
    const result = await this.userService.removeUserProfile(id, user);
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `The user has been successfully deactivated.`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return res.status(HttpStatus.OK).json(result);
  }

  @Delete()
  @UseGuards(JwtAuthGuard, UserDeactivatedGuard)
  @ApiBearerAuth()
  @ApiOkResponse({ description: 'Return delete user successfully' })
  @ApiOperation({ summary: 'Delete user' })
  @ApiCreatedResponse({
    description: 'The user has been successfully deactivated.',
  })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  async deleteUser(@Res() res, @Req() req, @GetUser() user: JwtPayload) {
    const result = await this.userService.removeUser(user);
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `The user has been successfully deactivated.`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return res.status(HttpStatus.OK).json(result);
  }

  @Auth()
  @Roles(UserRole.online)
  @Delete('/deleteMobileApp')
  @ApiOkResponse({ description: 'Return delete user successfully' })
  @ApiOperation({ summary: 'Delete user' })
  @ApiCreatedResponse({
    description: 'The user has been successfully deactivated.',
  })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  async deleteMobileApp(@Res() res, @Req() req, @GetUser() user: JwtPayload) {
    const result = await this.userService.removeMobileApp(user);
    try {
      await this.userService.sysLogUserSave({
        req,
        response: {
          status: HttpStatus.CREATED,
          message: `The user has been successfully delete in the mobile.`,
        },
        description: 'Log captured!!',
      });
    } catch (error) {
      console.log(error);
    }
    return res.status(HttpStatus.OK).json(result);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, UserDeactivatedGuard)
  @ApiOperation({ summary: 'Send email to confirm' })
  @ApiParam({ name: 'email' })
  @Patch('/sendEmail/:email')
  async sendEmail(
    @GetUser() user: JwtPayload,
    @Res() res,
    @Req() req,
    @Param('email') emailAddress,
  ): Promise<CustomResult> {
    if (!isEmail(emailAddress))
      throw new BadRequestException('formato invalido de correo.');
    console.log(emailAddress);
    const data = await this.userService
      .confirmEmail(user, emailAddress)
      .then((result) => {
        if (result?.emailData) {
          this.emailConfirmationService.sendVerificationLink(result.emailData);
          return result.result;
        }
        throw new Error(`Could not find confirmation`);
      })
      .catch((err) => {
        throw new Error(err);
      });

    if (data) {
      try {
        await this.userService.sysLogUserSave({
          req,
          response: {
            status: HttpStatus.CREATED,
            message: `Send email to confirm`,
          },
          description: 'Log captured!!',
        });
      } catch (error) {
        console.log(error);
      }
      return res.status(HttpStatus.OK).json(data.result);
    }

    return res.status(HttpStatus.BAD_REQUEST).json(data.result);
  }
}
