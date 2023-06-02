import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth, ApiQuery, ApiTags } from '@nestjs/swagger';
import { CreatePostDto, UpdatePostDto } from 'src/dto/post-dto';
import { PostsService } from './posts.service';

@ApiTags('posts')
@Controller('posts')
export class PostsController {
  constructor(private postService: PostsService) {}

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Post('/create-post')
  async createPost(@Req() req: any, @Body() cretePostDto: CreatePostDto) {
    return await this.postService.createPost(req, cretePostDto);
  }

  @ApiBearerAuth()
  @Get('/:userId/post-count')
  async postCount(@Param('userId') userId: string) {
    return await this.postService.postCount(userId);
  }

  @ApiQuery({
    name: 'tag',
    required: false,
    isArray: true,
  })
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Get('/tag')
  async getPosts(@Req() req: any, @Query() tag: string) {
    return await this.postService.getPosts(req, tag);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Put('/:postId')
  async updatePosts(
    @Req() req: any,
    @Param('postId') postId: string,
    @Body() updatePostDto: UpdatePostDto,
  ) {
    return await this.postService.updatePost(req, postId, updatePostDto);
  }

  @ApiBearerAuth()
  @Delete('/:postId')
  async deletePostById(@Param('postId') postId: string) {
    return await this.postService.deletePostById(postId);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Delete()
  async deletePosts(@Req() req: any) {
    return await this.postService.deletePostsOfUser(req);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Get('/pending-post')
  async pendingPost(@Req() req: any) {
    return await this.postService.pendingPost(req);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Get('/approved-post')
  async approvedPost(@Req() req: any) {
    return await this.postService.approvedPost(req);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Get('/rejected-post')
  async rejectedPost(@Req() req: any) {
    return await this.postService.rejectedPost(req);
  }
}
