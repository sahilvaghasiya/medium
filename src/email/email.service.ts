import { Injectable } from '@nestjs/common';
import * as sgMail from '@sendgrid/mail';
import { InvitationDto } from 'src/dto/auth-dto';
import { generateOTPCode } from 'src/utils/codeGenerator';

@Injectable()
export class EmailService {
  constructor() {
    sgMail.setApiKey(process.env.MAIL_API);
  }

  async sendVerificationEmail(to: string, user: string, otp: string) {
    const message = {
      to,
      from: 'sahilvaghasiya000@gmail.com',
      subject: 'LogIn verification',
      templateId: 'd-c1b35a54f778492bbc0bd6c963594349',
      dynamicTemplateData: {
        text: `Hi ${user}\n,\nYour logIn verification code is: ${otp}`,
        html: `Hi ${user},<br><br>Your logIn verification code is: ${otp}`,
      },
    };
    await sgMail.send(message);
  }

  async sendInvitation(to: string, invitationDto: InvitationDto) {
    const invitationLink = 'https://Medium.com/invitation';
    const randomNumber = generateOTPCode(12);
    const role = invitationDto.role;
    const message = {
      to,
      from: 'sahilvaghasiya000@gmail.com',
      subject: 'Invitation',
      templateId: 'd-8fd71b94ed754ea2abbf8f0c6402b4d1',
      dynamicTemplateData: {
        text: `hi, \nyou have been invited to join our community.\n you are invited for: ${role}.\nHere is your invitation link: ${invitationLink} and your Secret code for signUp is: ${randomNumber}`,
        html: `Hi,<br>you have been invited to join our community.\n Here is your invitation link: ${invitationLink} and your Secret code for signUp is: ${randomNumber}`,
      },
    };
    await sgMail.send(message);
  }
}
