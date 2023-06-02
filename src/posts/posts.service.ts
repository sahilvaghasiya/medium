import { Injectable } from '@nestjs/common';
import { PrismaClient, Status } from '@prisma/client';
import { CreatePostDto, UpdatePostDto } from 'src/dto/post-dto';
import { UserService } from '../user/user.service';

@Injectable()
export class PostsService {
  constructor(private prisma: PrismaClient, private userService: UserService) {}

  async createPost(req: any, createPostDto: CreatePostDto) {
    const { tag, title, body } = createPostDto;
    const checkUser = await this.userService.getUserById(req.user.id);
    if (!checkUser) {
      throw new Error('user not found');
    }
    await this.prisma.post.create({
      data: {
        createdBy: req.user.id,
        tag,
        title,
        body,
        status: Status.PENDING,
      },
    });
    if (!tag || tag.length === 0) {
      throw new Error('select right tag for your post');
    }
    return { message: 'post sent to admin for review' };
  }

  async postCount(userId: string) {
    return await this.prisma.post.count({
      where: {
        createdBy: userId,
      },
    });
  }

  async updatePost(req: any, postId: string, updatePostDto: UpdatePostDto) {
    const { title, body } = updatePostDto;
    const checkUser = await this.userService.getUserById(req.user.id);
    if (!checkUser) {
      throw new Error('user not found');
    }
    await this.prisma.post.update({
      where: {
        id: postId,
      },
      data: {
        title,
        body,
        status: Status.PENDING,
      },
    });
    return { message: 'updatedPost is sent to admin for review' };
  }

  async getPosts(req: any, filter: any) {
    const checkUser = await this.userService.getUserById(req.user.id);
    if (!checkUser) {
      throw new Error('user not found');
    }
    const postCount = await this.prisma.post.count({
      where: {
        tag: { has: filter.tag },
        createdBy: req.user.id,
      },
    });
    const posts = await this.prisma.post.findMany({
      where: {
        createdBy: req.user.id,
        tag: { has: filter.tag },
      },
    });
    return {
      postCount,
      posts,
    };
  }

  async deletePostsOfUser(req: any) {
    const checkUser = await this.userService.getUserById(req.user.id);
    if (!checkUser) {
      throw new Error('user not found');
    }
    const user = await this.prisma.post.deleteMany({
      where: {
        createdBy: req.user.id,
      },
    });
    return user;
  }

  async deletePostById(postId: string) {
    const post = await this.prisma.post.deleteMany({
      where: {
        id: postId,
      },
    });
    return post;
  }

  async pendingPost(req: any) {
    const checkUser = await this.userService.getUserById(req.user.id);
    if (!checkUser) {
      throw new Error('user not found');
    }
    const post = await this.prisma.post.findMany({
      where: {
        createdBy: req.user.id,
        status: Status.PENDING,
      },
    });
    const postCount = await this.prisma.post.count({
      where: {
        createdBy: req.user.id,
        status: Status.PENDING,
      },
    });
    return {
      postCount,
      post,
    };
  }

  async approvedPost(req: any) {
    const checkUser = await this.userService.getUserById(req.user.id);
    if (!checkUser) {
      throw new Error('user not found');
    }
    const post = await this.prisma.post.findMany({
      where: {
        createdBy: req.user.id,
        status: Status.APPROVED,
      },
    });
    if (!post) {
      throw new Error('there is no any posts found');
    }
    const postCount = await this.prisma.post.count({
      where: {
        createdBy: req.user.id,
        status: Status.APPROVED,
      },
    });
    return {
      postCount,
      post,
    };
  }

  async rejectedPost(req: any) {
    const checkUser = await this.userService.getUserById(req.user.id);
    if (!checkUser) {
      throw new Error('user not found');
    }
    const post = await this.prisma.post.findMany({
      where: {
        createdBy: req.user.id,
        status: Status.REJECTED,
      },
    });
    const postCount = await this.prisma.post.count({
      where: {
        createdBy: req.user.id,
        status: Status.REJECTED,
      },
    });
    return {
      postCount,
      post,
    };
  }
}
