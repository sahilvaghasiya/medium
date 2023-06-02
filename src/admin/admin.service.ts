import { Injectable } from '@nestjs/common';
import { HttpErrorByCode } from '@nestjs/common/utils/http-error-by-code.util';
import { JwtService } from '@nestjs/jwt';
import { PrismaClient, Status } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { AdminLogInDto, CreateAdminDto } from 'src/dto/admin-dto';
import { ReviewPostDto } from 'src/dto/post-dto';
import { jwtSecret } from './constant';

@Injectable()
export class AdminService {
  constructor(private prisma: PrismaClient, private jwt: JwtService) {}

  private hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async signUp(createAdminDto: CreateAdminDto) {
    const { email, password, phone, name } = createAdminDto;
    const existingAdmin = await this.prisma.admin.findUnique({
      where: { email },
    });
    if (existingAdmin) {
      throw new HttpErrorByCode[409]('Email already exists');
    }
    if (!password) {
      throw new HttpErrorByCode[400](' Password must be required ');
    }
    if (password.length != 8) {
      throw new HttpErrorByCode[400]('Enter valid password');
    }
    const passwordHash = await this.hashData(password);
    const admin = await this.prisma.admin.create({
      data: {
        email,
        password: passwordHash,
        phone,
        name,
      },
    });
    return {
      admin,
    };
  }

  async logIn(req: any, adminLogInDto: AdminLogInDto) {
    const admin = await this.getAdminByEmail(req, adminLogInDto.email);
    if (!admin) {
      throw new HttpErrorByCode[400]('Invalid email');
    }
    const passwordMatches: boolean = await bcrypt.compare(
      adminLogInDto.password,
      admin.password,
    );
    if (!passwordMatches) {
      throw new HttpErrorByCode[400]('Invalid Password');
    }
    const token = await this.signToken({
      id: admin.id,
      email: admin.email,
      name: admin.name,
    });
    const ss = await this.prisma.session.create({
      data: {
        adminId: admin.id,
        token,
      },
    });
    return ss;
  }

  async signToken(args: { id: string; email: string; name: string }) {
    const payload = args;
    return this.jwt.signAsync(payload, { secret: jwtSecret });
  }

  async getAdminByEmail(req: any, email: string) {
    const admin = await this.prisma.admin.findUnique({
      where: { email },
    });
    return admin;
  }

  async logout(req: any) {
    try {
      const checkAdmin = await this.getAdminById(req.user.id);
      if (!checkAdmin) {
        throw new HttpErrorByCode[404]('adminId not found');
      }
      console.log(checkAdmin);
      const session = await this.prisma.session.deleteMany({
        where: { adminId: req.user.id },
      });
      if (session.count == 0) {
        return { message: 'no session found' };
      }
      return { message: 'Sessions deleted successfully' };
    } catch (error) {
      throw new HttpErrorByCode[400](
        'Invalid adminId or admin already logged out',
      );
    }
  }

  async getAdminById(id: string) {
    if (!id) {
      throw new HttpErrorByCode[400]('adminId not provided');
    }
    const admin = await this.prisma.admin.findUnique({
      where: { id: id },
    });
    if (!admin) {
      throw new HttpErrorByCode[404]('admin not found for this userId');
    }
    return admin;
  }

  async getPostForReview(req: any) {
    const checkAdmin = await this.getAdminById(req.user.id);
    if (!checkAdmin) {
      throw new HttpErrorByCode[404]('adminId not found');
    }
    const posts = await this.prisma.post.findMany({
      where: { status: Status.PENDING },
    });
    if (!posts) {
      throw new Error('there are not any pending posts for review');
    }
    const postCount = await this.prisma.post.count({
      where: {
        status: Status.PENDING,
      },
    });
    return {
      postCount,
      posts,
    };
  }

  async reviewPost(req: any, postId: string, reviewPostDto: ReviewPostDto) {
    const checkAdmin = await this.getAdminById(req.user.id);
    if (!checkAdmin) {
      throw new HttpErrorByCode[404]('adminId not found');
    }
    const post = await this.prisma.post.findUnique({
      where: {
        id: postId,
      },
    });
    if (!post) {
      throw new HttpErrorByCode[404]('post not found');
    }
    if (post.status !== 'PENDING') {
      return {
        post,
        msg: new HttpErrorByCode[400]('post is already reviewed'),
      };
    }
    const { status } = reviewPostDto;
    const review = await this.prisma.post.update({
      where: {
        id: postId,
      },
      data: {
        status: status,
      },
    });
    let message;
    if (review.status == 'APPROVED') {
      message = 'post approved, Thank You😊';
    } else if (review.status == 'REJECTED') {
      message = 'post rejected, sorry😒';
    }
    return {
      review,
      message,
    };
  }
}
