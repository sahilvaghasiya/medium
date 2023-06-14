import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { PostsModule } from './posts/posts.module';
import { UserModule } from './user/user.module';
import { AdminModule } from './admin/admin.module';
import { EmailService } from './email/email.service';
@Module({
  imports: [UserModule, AuthModule, PostsModule, AdminModule],
  controllers: [AppController],
  providers: [AppService, EmailService],
})
export class AppModule {}
