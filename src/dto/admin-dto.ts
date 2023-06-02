import { ApiProperty, PartialType } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

export class CreateAdminDto {
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
}

export class AdminLogInDto {
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
}

export class EditAdminDto extends PartialType(CreateAdminDto) {}
