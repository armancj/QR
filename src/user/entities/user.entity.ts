import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  JoinTable,
  ManyToMany,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { UserRole } from '../../common/enums/userRole';
import * as bcrypt from 'bcrypt';
import { UserStatus } from '../../common/enums/userStatus';
import { Subscription } from '../../subscriptions/entities/subscription.entity';
import { CreditCards } from '../../credit-cards/entities/credit-cards.entity';
import { SysLog } from '../../sys-logs/entities/sys-log.entity';
import { Exclude } from 'class-transformer';
import { MobileApp } from './mobile-app.entity';

@Entity('users')
export class User extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', nullable: true })
  name: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  lastname: string;

  @Column({ type: 'varchar', nullable: true, unique: true })
  username: string;

  @Column({ type: 'varchar', length: 255, nullable: false, unique: true })
  email: string;

  @Column({ default: false })
  isEmailConfirmed: boolean;

  @Column({ type: 'varchar', nullable: false })
  password: string;

  @Column({ nullable: true })
  salt: string;

  @Column('integer', { nullable: true })
  activateCode: number;

  @Column('timestamp', { nullable: true })
  expireCode: Date;

  @Column({ default: UserRole.online })
  role: string;

  @Column({ nullable: true })
  stripeCustomerId: string;

  @Column({ nullable: true })
  cardCustomerId?: string;

  /*@Column({ nullable: true })
  avatar?: string;*/

  @JoinTable()
  @ManyToMany(() => Subscription, (subscription) => subscription.users, {
    cascade: true,
    nullable: true,
  })
  subscriptions?: Subscription[];

  @Column({ nullable: true })
  subscriptionStatus?: string;

  @Column({ default: UserStatus.activated })
  status: string;

  @CreateDateColumn({ type: 'date' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'date' })
  updateAt: Date;

  @OneToMany(() => CreditCards, (creditCard) => creditCard.user, {
    cascade: true,
    nullable: true,
  })
  creditCards: CreditCards[];

  @Exclude()
  @OneToMany(() => SysLog, (sysLog) => sysLog.createdBy, {
    nullable: true,
  })
  sysLog: SysLog[];

  @Column({
    nullable: true,
  })
  currentHashedRefreshToken: string;

  @Column({
    nullable: true,
  })
  currentHashedRefreshTokenMobile: string;

  @OneToMany(() => MobileApp, (mobile_apps) => mobile_apps.user, {
    cascade: true,
    nullable: true,
  })
  mobile_apps?: MobileApp[];

  async validatePassword(password: string): Promise<boolean> {
    const hash = await bcrypt.hash(password, this.salt);
    return hash === this.password;
  }
}
