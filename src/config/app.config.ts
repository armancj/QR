import { join } from 'path';

export default () => ({
  environment: process.env.NODE_ENV || 'development',
  database: {
    type: 'postgres',
    host: process.env.POSTGRES_SERVICE_HOST,
    port: parseInt(process.env.POSTGRES_SERVICE_PORT, 10),
    username: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
    database: process.env.POSTGRES_DB,
    entities: [join(__dirname + '../**/**/*.entity{.ts,.js}')],
    autoLoadEntities: true,
    // Implements Migrations
    /** Recourse
     * * https://typeorm.io/#/migrations
     */
    // migrationsRun: true,
    migrations: [join(__dirname + '../migration/**/*{.ts,.js}')],
    cli: {
      entitiesDir: 'dist/**/*.entity{.ts,.js}',
      migrationsDir: 'src/migrations/',
    },

    // Activated only manually at development if is need (deactivate at)
    synchronize: process.env.synchronize || false,
    logging: process.env.synchronize || false,
    // logger: new DatabaseLogger(),
  },
});
