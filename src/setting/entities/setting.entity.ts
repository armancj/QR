import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity()
export class Setting {
  @PrimaryGeneratedColumn('uuid')
  uuid?: string;

  @Column('varchar', { unique: true })
  name: string;

  @Column('varchar')
  value: string;

  @Column('varchar', { nullable: true })
  description?: string;

  @Column('boolean', { default: false })
  active: boolean;

  @CreateDateColumn()
  createAt?: Date;

  @UpdateDateColumn()
  updateAt?: Date;

  @Column('boolean', { default: false })
  isPublic?: boolean;
}
