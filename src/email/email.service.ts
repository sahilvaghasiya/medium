import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import * as postmark from 'postmark';

@Injectable()
export class EmailService {
  prisma: PrismaClient;
  client: postmark.ServerClient;
  constructor() {
    this.client = new postmark.ServerClient(process.env.MAIL_API);
  }

  async sendVerificationEmail(to: string, user: string, otp: string) {
    const message: postmark.TemplatedMessage = {
      From: 'sahil_19172@ldrp.ac.in',
      To: to,
      TemplateAlias: 'code-your-own',
      TemplateModel: {
        User: user,
        verificationCode: otp,
      },
    };
    await this.client.sendEmailWithTemplate(message);
  }

  async sendInvitation(
    to: string,
    role: string,
    invitationCode: string,
    name: string,
    phoneNumber: string,
  ) {
    const invitationLink =
      'http://localhost:3000/api#/auth/AuthController_confirmSignUp';
    const Message: postmark.TemplatedMessage = {
      From: 'sahil_172@ldrp.ac.in',
      To: to,
      TemplateAlias: 'user-invitation',
      TemplateModel: {
        sender_name: name,
        role: role,
        Subject: 'Invitation to join',
        invitation_link: invitationLink,
        invitation_code: invitationCode,
        phone_number: phoneNumber,
      },
    };
    await this.client.sendEmailWithTemplate(Message);
  }
}
