import {
  Body,
  Controller,
  Get,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import {
  AuthDto,
  ChangePasswordDto,
  InvitationDto,
  LoginOTPDto,
  SignUpDto,
} from 'src/dto/auth-dto';
import { AuthService } from './auth.service';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/sign-up')
  async signUp(@Body() signUpDto: SignUpDto) {
    return await this.authService.signUp(signUpDto);
  }

  @Post('/sign-in')
  async logIn(@Req() req: any, @Body() authDto: AuthDto) {
    return await this.authService.logIn(req, authDto);
  }

  // @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Post('/account/verify')
  async verifyLogIn(@Req() req: any, @Body() loginOTPDto: LoginOTPDto) {
    return await this.authService.verifyLogIn(req, loginOTPDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Post('/InviteUser')
  async inviteUser(@Req() req: any, @Body() invitationDto: InvitationDto) {
    return await this.authService.inviteUser(req, invitationDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Post('/sign-out')
  async logOut(@Req() req: any) {
    return await this.authService.logout(req);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Get('/whoAmI')
  async whoAmI(@Req() req: any) {
    return await this.authService.whoAmI(req);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Put('change-password')
  async changePassword(
    @Req() req: any,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    return await this.authService.changePassword(req, changePasswordDto);
  }
}
