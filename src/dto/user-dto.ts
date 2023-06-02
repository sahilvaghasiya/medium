import { ApiProperty, PartialType } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

export class CreateUserDto {
  @ApiProperty()
  @IsEmail(undefined, { message: 'enter valid emailId' })
  @IsNotEmpty({ message: 'emailId is required' })
  email: string;

  @ApiProperty()
  @IsString({ message: 'password must be in string' })
  @IsNotEmpty({ message: 'password is required' })
  @MinLength(8, { message: 'password must be 8 character long' })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'enter password in proper way',
  })
  password: string;

  @ApiProperty()
  @IsString({ message: 'enter your name' })
  @IsOptional()
  @Matches(/^[A-Z][a-z]*$/, {
    message: 'enter name in proper way',
  })
  name?: string;

  @ApiProperty()
  @IsString({ each: true, message: 'Role must be a string' })
  @IsNotEmpty({ message: 'At least one role must be provided' })
  role: string;
}

export class UserLogInDto {
  @IsEmail(undefined, { message: 'enter valid emailId' })
  @IsNotEmpty({ message: 'emailId is required' })
  email: string;

  @IsString({ message: 'password must be in string' })
  @IsNotEmpty({ message: 'password is required' })
  @MinLength(8, { message: 'password must be 8 character long' })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'enter password in proper way',
  })
  password: string;
}

export class UpdateUserDto extends PartialType(CreateUserDto) {}
