import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { PrismaClient } from '@prisma/client';
import { PrismaModule } from 'prisma/prisma.module';
import { PostsService } from 'src/posts/posts.service';
import { UserModule } from 'src/user/user.module';
import { UserService } from 'src/user/user.service';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { jwtSecret } from './constant';
import { JwtStrategy } from './jwt.strategy';
import { EmailService } from 'src/email/email.service';

@Module({
  imports: [
    PrismaModule,
    PassportModule,
    UserModule,
    JwtModule.register({
      secret: jwtSecret,
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    UserService,
    PostsService,
    PrismaClient,
    JwtStrategy,
    EmailService,
  ],
})
export class AuthModule {}
