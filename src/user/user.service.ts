import { Injectable } from '@nestjs/common';
import { HttpErrorByCode } from '@nestjs/common/utils/http-error-by-code.util';
import { PrismaClient, Role, User } from '@prisma/client';
import { UpdateUserDto } from 'src/dto/user-dto';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaClient) {}

  async getUsers() {
    const users = await this.prisma.user.findMany();
    return users;
  }

  async getUserById(_id: string): Promise<User> {
    if (!_id) {
      throw new HttpErrorByCode[400]('userId not provided');
    }
    const user = await this.prisma.user.findUnique({
      where: { id: _id },
      include: { posts: true },
    });
    if (!user) {
      throw new HttpErrorByCode[404]('user not found for this userId');
    }
    return user;
  }

  async updateUser(req: any, updateUserDto: UpdateUserDto): Promise<User> {
    const { email, name } = updateUserDto;
    const checkUser = await this.getUserById(req.user.id);
    if (!checkUser) {
      throw new HttpErrorByCode[404]('user not found');
    }
    return await this.prisma.user.update({
      where: { id: req.user.id },
      data: {
        email,
        name,
      },
    });
  }

  async getUserByEmail(req: any, email: string) {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });
    return user;
  }

  async deleteUser(req: any): Promise<User> {
    const checkUser = await this.getUserById(req.user.id);
    if (!checkUser) {
      throw new HttpErrorByCode[400]('user not found');
    }
    await this.prisma.post.deleteMany({
      where: {
        createdBy: req.user.id,
      },
    });
    return await this.prisma.user.delete({
      where: {
        id: req.user.id,
      },
    });
  }

  async updateEmailVerificationStatus(
    userId: string,
    isEmailVerified: boolean,
  ) {
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        isEmailVerified,
      },
    });
  }

  async getUserByRole(email: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        email,
        role: Role.ADMIN,
      },
    });
    return user;
  }
}

export default UserService;
