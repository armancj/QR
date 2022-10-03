import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { AuthModule } from '../auth/auth.module';
import { StripeModule } from '../stripe/stripe.module';
import { EmailConfirmationModule } from '../email-confirmation/email-confirmation.module';
import { MinioApiModule } from '../minio-api/minio-api.module';
import { Subscription } from '../subscriptions/entities/subscription.entity';
import { MobileApp } from './entities/mobile-app.entity';
import { EnTvUsaEmail } from './entities/en-tv-usa-email.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Subscription, MobileApp, EnTvUsaEmail]),
    AuthModule,
    StripeModule,
    EmailConfirmationModule,
    MinioApiModule,
  ],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
