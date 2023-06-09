import { Injectable } from '@nestjs/common';
import { HttpErrorByCode } from '@nestjs/common/utils/http-error-by-code.util';
import { JwtService } from '@nestjs/jwt';
import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import {
  AuthDto,
  ChangePasswordDto,
  LoginOTPDto,
  SignUpDto,
} from 'src/dto/auth-dto';
import { PostsService } from 'src/posts/posts.service';
import { generateOTP, generateOTPCode } from 'src/utils/codeGenerator';
// import { getExpiry } from 'src/utils/dateTimeUtility';
import * as sgMail from '@sendgrid/mail';
import { UserService } from '../user/user.service';
import { jwtSecret } from './constant';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaClient,
    private jwt: JwtService,
    private userService: UserService,
    private postsService: PostsService,
  ) {}

  private hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async signUp(signUpDto: SignUpDto) {
    const { email, password, phone, name } = signUpDto;
    const passwordHash = await this.hashData(password);
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (existingUser) {
      throw new HttpErrorByCode[409]('Email already exists');
    }
    if (!password) {
      throw new HttpErrorByCode[400](' Password must be required ');
    }
    if (password.length != 8) {
      throw new HttpErrorByCode[400]('Enter valid password');
    }
    const user = await this.prisma.user.create({
      data: {
        email,
        password: passwordHash,
        name,
        phone,
        role: Role.USER,
      },
    });
    await this.prisma.userCredential.create({
      data: {
        user: {
          connect: {
            id: user.id,
          },
        },
        password: user.password,
        otp: {
          create: {
            code: undefined,
            expiresAt: undefined,
          },
        },
      },
    });
    return {
      user,
    };
  }

  async logIn(req: any, authDto: AuthDto) {
    const user = await this.userService.getUserByEmail(req, authDto.email);
    if (!user) {
      throw new HttpErrorByCode[400]('Invalid email');
    }
    const passwordMatches: boolean = await bcrypt.compare(
      authDto.password,
      user.password,
    );
    if (!passwordMatches) {
      throw new HttpErrorByCode[400]('Invalid Password');
    }
    let otp;
    let otpCode;
    // const expiresAt = getExpiry();
    if (user.isEmailVerified == false || user.isEmailVerified == true) {
      otp = generateOTP(6);
      otpCode = generateOTPCode(10);
      await this.prisma.userCredential.update({
        where: {
          userId: user.id,
        },
        data: {
          otp: {
            code: otp,
            oToken: otpCode,
            // expiresAt: expiresAt.toISOString(),
          },
        },
      });
      const message = {
        to: 'sp95108s.p@gmail.com',
        from: 'sahilvaghasiya000@gmail.com',
        subject: 'LogIn verification',
        templateId: 'd-c1b35a54f778492bbc0bd6c963594349',
        dynamicTemplateData: {
          text: `
          Hi, ${user.name},
          your logIn verification code is: ${otp} and your token for logIn is: ${otpCode}`,
          html: `<p> your logIn verification code is: ${otp} and your token for logIn is: ${otpCode}</p>`,
        },
      };

      await sgMail.send(message);
      return {
        message:
          'now, verify your account with otp which is sent to your email',
        // expiresAt: expiresAt.toISOString(),
      };
    }
    const token = await this.signToken({
      id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
    });
    return {
      message: `your account is already verified, so you can directly use this token: ${token}`,
    };
  }

  async signToken(args: {
    id: string;
    email: string;
    name: string;
    phone: string;
  }) {
    const payload = args;
    return this.jwt.signAsync(payload, { secret: jwtSecret });
  }

  async verifyLogIn(req: any, loginOTPDto: LoginOTPDto) {
    const { oToken, code } = loginOTPDto;
    console.log(loginOTPDto);
    // const expiresAt = getExpiry();
    const userCredential = await this.prisma.userCredential.findFirst({
      where: {
        otp: {
          equals: {
            code,
            oToken,
            // expiresAt: expiresAt.toISOString(),
          },
        },
      },
    });
    console.log(userCredential);
    if (userCredential) {
      await this.userService.updateEmailVerificationStatus(
        userCredential.userId,
        true,
      );
      const final = await this.userService.getUserById(userCredential.userId);
      const token = await this.signToken({
        id: final.id,
        email: final.email,
        name: final.name,
        phone: final.phone,
      });
      await this.prisma.session.create({
        data: {
          userId: final.id,
          token: token,
        },
      });
      return {
        final,
        token,
      };
    } else {
      throw new Error('invalid credentials');
    }
  }

  async logout(req: any) {
    try {
      const checkUser = await this.userService.getUserById(req.user.id);
      if (!checkUser) {
        throw new HttpErrorByCode[404]('userId not found');
      }
      const session = await this.prisma.session.deleteMany({
        where: { userId: req.user.id },
      });
      if (session.count == 0) {
        return { message: 'no session found' };
      }
      return { message: 'Sessions deleted successfully' };
    } catch (error) {
      throw new HttpErrorByCode[400](
        'Invalid userId or user already logged out',
      );
    }
  }

  async changePassword(req: any, changePasswordDto: ChangePasswordDto) {
    const { password, newPassword } = changePasswordDto;
    const checkUser = await this.userService.getUserById(req.user.id);
    if (!checkUser) {
      throw new HttpErrorByCode[404]('userId not found');
    }
    const matchPassword = await bcrypt.compare(password, checkUser.password);
    if (!matchPassword) {
      throw new HttpErrorByCode[400]('invalid password');
    }
    await this.prisma.user.update({
      where: { id: req.user.id },
      data: { password: bcrypt.hashSync(newPassword, 8) },
    });
    return {
      message: 'Password changed successfully',
    };
  }

  async whoAmI(req: any) {
    const checkUser = await this.userService.getUserById(req.user.id);
    if (!checkUser) {
      throw new HttpErrorByCode[404]('userId not found');
    }
    const user = await this.prisma.user.findUnique({
      where: { id: req.user.id },
    });
    if (!user) {
      throw new HttpErrorByCode[400]('sorry');
    }
    return user;
  }
}
