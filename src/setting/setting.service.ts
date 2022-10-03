import { Injectable, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { FindManyOptions, Repository } from 'typeorm';
import { CreateSettingDto } from './dto/create-setting.dto';
import { UpdateSettingDto } from './dto/update-setting.dto';
import { Setting } from './entities/setting.entity';
import { ConfigService } from '@nestjs/config';
import {
  FRONTEND_URL,
  HOST,
  JWT_ACCESS_TOKEN_EXPIRATION_TIME,
  JWT_REFRESH_TOKEN_EXPIRATION_TIME,
  PORT,
  SENTRY_DSN,
} from '../config/constants';

@Injectable()
export class SettingService implements OnModuleInit {
  private _settingBD: Map<string, string> = new Map();
  constructor(
    @InjectRepository(Setting)
    private readonly settingRepository: Repository<Setting>,
    private readonly configService: ConfigService,
  ) {}
  async onModuleInit() {
    await this.loadSetting();
  }

  private async loadSetting() {
    this._settingBD = new Map();
    const onBd = await this.settingRepository.find({
      where: { active: true },
    });
    console.log('Loading setting..');

    onBd.forEach((v) => {
      this._settingBD.set(v.name, v.value);
    });
    console.log('Setting Loaded..');
    return {
      message: 'Setting Update Successfully!!',
    };
  }

  async createVar(dto: CreateSettingDto) {
    return this.settingRepository.save(dto).then(() => {
      return this.loadSetting();
    });
  }

  async updateVar(uuid: string, dto: UpdateSettingDto) {
    return this.settingRepository.update(uuid, dto).then(() => {
      return this.loadSetting();
    });
  }

  async getSetting() {
    return this.settingRepository.find();
  }

  async deleteVar(uuid: string) {
    return this.settingRepository
      .delete({
        uuid,
      })
      .then(async (v) => {
        await this.loadSetting();
        return v;
      });
  }
  get(key: string): string | null {
    if (this._settingBD.has(key)) return this._settingBD.get(key);
    else return null;
  }

  async isActive(key: string): Promise<boolean> {
    const seting = await this.settingRepository.findOne({
      where: {
        name: key,
      },
    });
    if (!seting) return false;
    else {
      if (seting.active) return true;

      return false;
    }
  }

  async getPublicVars() {
    return this.settingRepository.find({
      where: { isPublic: true },
    });
  }

  async set(name: string, value: string) {
    const sVar = await this.settingRepository.findOne({ where: { name } });
    if (!sVar) {
      const seting: Setting = {
        name: name,
        value: value,
        active: true,
        isPublic: false,
      };

      await this.settingRepository.save(seting);
    } else
      await this.settingRepository.update(
        {
          name,
        },
        {
          value,
        },
      );

    await this.loadSetting();
  }

  async getVar(opt: FindManyOptions<Setting>) {
    return this.settingRepository.findOne(opt);
  }

  async getSettingEnv() {
    return {
      host: process.env.POSTGRES_SERVICE_HOST,
      port: parseInt(process.env.POSTGRES_SERVICE_PORT, 10),
      username: process.env.POSTGRES_USER,
      password: process.env.POSTGRES_PASSWORD,
      database: process.env.POSTGRES_DB,
      PORT: this.configService.get<string>(PORT) || 'not found',
      FRONTEND_URL: this.configService.get<string>(FRONTEND_URL) || 'not found',
      HOST: this.configService.get<string>(HOST) || 'not found',
      JWT_ACCESS_TOKEN_EXPIRATION_TIME:
        this.configService.get<string>(JWT_ACCESS_TOKEN_EXPIRATION_TIME) ||
        'not found',
      JWT_REFRESH_TOKEN_EXPIRATION_TIME:
        this.configService.get<string>(JWT_REFRESH_TOKEN_EXPIRATION_TIME) ||
        'not found',
      SENTRY_DSN: this.configService.get<string>(SENTRY_DSN) || 'not found',
    };
  }
}
