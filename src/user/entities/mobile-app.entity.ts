import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from './user.entity';

@Entity('mobile_app')
export class MobileApp extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @CreateDateColumn({ type: 'date' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'date' })
  updateAt: Date;

  @ManyToOne(() => User, (user) => user.mobile_apps, {
    nullable: true,
  })
  user: User;

  @Column({
    nullable: true,
  })
  currentHashedRefreshToken: string;
}
