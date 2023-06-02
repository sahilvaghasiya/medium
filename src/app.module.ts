import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { PostsModule } from './posts/posts.module';
import { UserModule } from './user/user.module';
import { AdminModule } from './admin/admin.module';
// import { TwilioService } from './twilio/twilio.service';
import { EmailService } from './email/emailVerification.service';
import { EmailModule } from './email/emailVerification.module';

@Module({
  imports: [UserModule, AuthModule, PostsModule, AdminModule, EmailModule],
  controllers: [AppController],
  providers: [AppService, EmailService],
})
export class AppModule {}
