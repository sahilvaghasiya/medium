import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { AdminLogInDto, CreateAdminDto } from 'src/dto/admin-dto';
import { ReviewPostDto } from 'src/dto/post-dto';
import { AdminService } from './admin.service';

@ApiTags('admin')
@Controller('admin')
export class AdminController {
  constructor(private adminService: AdminService) {}

  @Post('/sign-up')
  async signUp(@Body() createAdminDto: CreateAdminDto) {
    return await this.adminService.signUp(createAdminDto);
  }

  @Post('/sign-in')
  async logIn(@Req() req: any, @Body() adminLogInDto: AdminLogInDto) {
    return await this.adminService.logIn(req, adminLogInDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Get('/posts')
  async getPostForReview(@Req() req: any) {
    return await this.adminService.getPostForReview(req);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Post('/sign-out')
  async logOut(@Req() req: any) {
    return await this.adminService.logout(req);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Put('/post/review/:postId')
  async review(
    @Req() req: any,
    @Param('postId') postId: string,
    @Body() reviewPostDto: ReviewPostDto,
  ) {
    return await this.adminService.reviewPost(req, postId, reviewPostDto);
  }
}
