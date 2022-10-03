import { BaseEntity, Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { EmailTypeEnum } from '../enum/email-type.enum';

@Entity('en_tv_usa_email')
export class EnTvUsaEmail extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', nullable: true })
  name: string;

  //deleteUnique
  @Column({ type: 'varchar', length: 255, nullable: false })
  email: string;

  @Column({
    type: 'varchar',
    enum: EmailTypeEnum,
    length: 255,
    nullable: false,
  })
  type: EmailTypeEnum;

  @Column('integer', { nullable: true })
  activateCode: number;

  @Column('timestamp', { nullable: true })
  expireCode: Date;
}
