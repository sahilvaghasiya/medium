import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { UpdateUserDto } from '../dto/user-dto';
import { UserService } from './user.service';

@ApiTags('user')
@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Get('/getAll')
  async getUsers() {
    return await this.userService.getUsers();
  }

  @ApiBearerAuth()
  @Get('/:_id')
  async getUser(@Param('_id') _id: string) {
    return await this.userService.getUserById(_id);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Put('/')
  update(@Req() req: any, @Body() updateUserDto: UpdateUserDto) {
    return this.userService.updateUser(req, updateUserDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Delete('')
  async deleteUser(@Req() req: any) {
    return await this.userService.deleteUser(req);
  }
}
