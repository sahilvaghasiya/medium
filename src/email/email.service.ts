import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import * as sgMail from '@sendgrid/mail';
import { generateOTPCode } from 'src/utils/codeGenerator';

@Injectable()
export class EmailService {
  prisma: PrismaClient;
  constructor() {
    sgMail.setApiKey(process.env.MAIL_API);
  }

  async sendVerificationEmail(to: string, user: string, otp: string) {
    const message = {
      to,
      from: 'svaghasiya000@gmail.com',
      subject: 'LogIn verification',
      templateId: 'd-7594df463b9548a9b0cfd4a15fe64429',
      dynamicTemplateData: {
        text: `Hi ${user}\n,\nYour logIn verification code is: ${otp}`,
        html: `Hi ${user},<br><br>Your logIn verification code is: ${otp}`,
      },
    };
    await sgMail.send(message);
  }

  async sendInvitation(to: string, role: string) {
    const invitationLink = 'https://Medium.com/invitation';
    const randomNumber = generateOTPCode(16);
    const message = {
      to,
      from: 'svaghasiya000@gmail.com',
      subject: 'Invitation',
      templateId: 'd-71e49cb9e2544336bc9edef655cdf9e4',
      dynamicTemplateData: {
        text: `Hi, \nyou have been invited to join our community.\n you are invited for: ${role} role.\nHere is your invitation link: ${invitationLink} and your Secret code for signUp is: ${randomNumber}`,
        html: `Hi,<br>you have been invited to join our community.</br>\n<br> you are invited for: ${role} role.</br>\n <br>Here is your invitation link: ${invitationLink} and your Secret code for signUp is: ${randomNumber}</br>`,
      },
    };
    const result = await sgMail.send(message);
    console.log(result);
  }
}
