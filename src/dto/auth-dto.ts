// import { PartialType } from '@nestjs/mapped-types';
import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import {
  IsEmail,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

export class SignUpDto {
  @ApiProperty()
  @IsEmail(undefined, { message: 'enter valid emailId' })
  @IsNotEmpty({ message: 'emailId is required' })
  email: string;

  @ApiProperty()
  @IsString({ message: 'password must be in string' })
  @MinLength(8, { message: 'password must be 8 character long' })
  @IsNotEmpty({ message: 'password is required' })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'enter password in proper way',
  })
  password: string;

  @ApiProperty()
  @IsString({ message: 'PhoneNumber must be in string' })
  @Matches(/(\+91)?(-)?\s*?(91)?\s*?(\d{3})-?\s*?(\d{3})-?\s*?(\d{4})/, {
    message: 'enter phone number in proper way',
  })
  @IsNotEmpty({ message: 'phone is required' })
  phone: string;

  @ApiProperty()
  @IsString({ message: 'enter your name' })
  @IsOptional()
  @Matches(/^[A-Z][a-z]*$/, {
    message: 'enter name in proper way',
  })
  name?: string;

  @ApiProperty()
  @IsString({ message: 'Role is required' })
  @IsNotEmpty({ message: 'Role is required' })
  @IsIn(['ADMIN', 'USER'], { each: true, message: 'Invalid Role' })
  role: Role;
}

export class AuthDto {
  @ApiProperty()
  @IsEmail(undefined, { message: 'Enter valid email' })
  @IsNotEmpty({ message: 'Email address is required' })
  email: string;

  @ApiProperty()
  @IsString({ message: 'enter password in string formate' })
  @MinLength(8, { message: 'password must be have 8 char' })
  @IsNotEmpty({ message: 'password is required' })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'enter password in proper way',
  })
  password: string;
}

export class ChangePasswordDto {
  @ApiProperty()
  @IsNotEmpty({ message: 'password is required' })
  @IsString({ message: 'enter password in string formate' })
  @MinLength(8, { message: 'password must be have 8 char' })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'enter password in proper way',
  })
  password: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'password is required' })
  @IsString({ message: 'enter password in string formate' })
  @MinLength(8, { message: 'password must be have 8 char' })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'enter password in proper way',
  })
  newPassword: string;
}

export class LoginOTPDto {
  @ApiProperty()
  @IsNotEmpty({ message: 'please enter OTP' })
  @IsString({ message: 'enter otp in string formate' })
  code: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'please enter token' })
  @IsString({ message: 'enter token in string formate' })
  oToken: string;
}

export class InvitationDto {
  @ApiProperty()
  @IsNotEmpty({ message: 'please enter email' })
  @IsEmail(undefined, { message: 'enter valid emailId' })
  email: string;

  @ApiProperty()
  @IsString({ message: 'Role is required' })
  @IsNotEmpty({ message: 'Role is required' })
  @IsIn(['ADMIN', 'USER'], { each: true, message: 'Invalid Role' })
  role: Role;
}
