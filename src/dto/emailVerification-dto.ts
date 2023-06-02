import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class EmailVerificationDto {
  @ApiProperty()
  @IsString({ message: 'token must be in string' })
  @IsNotEmpty({ message: 'token in required' })
  otp: string;
}
