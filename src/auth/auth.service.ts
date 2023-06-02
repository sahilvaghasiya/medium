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
import { getExpiry } from 'src/utils/dateTimeUtility';
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
    const expiresAt = getExpiry();
    if (user.isEmailVerified == false) {
      otp = generateOTP(6);
      otpCode = generateOTPCode(10);
      await this.prisma.userCredential.update({
        where: {
          userId: user.id,
        },
        data: {
          otp: {
            update: {
              code: otp,
              oToken: otpCode,
              expiresAt: expiresAt,
            },
          },
        },
      });
      return {
        message: `now, verify your account with otp: ${otp}`,
        oToken: otpCode,
      };
    }
    // return {
    // token,
    // };
  }

  async signToken(args: { id: string; email: string; name: string }) {
    const payload = args;
    return this.jwt.signAsync(payload, { secret: jwtSecret });
  }

  // async verifyToken(oToken) {
  //   const userCredential = await this.prisma.userCredential.findUnique({
  //     where: {
  //       otp: {
  //         include: {
  //           oToken: oToken,
  //         },
  //       },
  //     },
  //   });
  //   if (!userCredential) {
  //     throw new HttpErrorByCode[400]('Invalid token');
  //   }
  //   return userCredential;
  // }

  async verifyLogIn(req: any, loginOTPDto: LoginOTPDto) {
    const { oToken, code } = loginOTPDto;
    const otp = await this.prisma.otp.findFirst({
      where: {
        oToken: oToken,
        code,
      },
      include: {
        UserCredential: {
          include: {
            user: true,
          },
        },
      },
    });
    if (otp) {
      const us = await this.prisma.userCredential.findFirst({
        where: {
          otpId: otp.id,
        },
      });
      const final = await this.userService.getUserById(us.userId);
      return final;
    } else {
      throw new HttpErrorByCode[400](' Invalid OTP ');
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
