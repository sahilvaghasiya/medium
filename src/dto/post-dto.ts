import { PartialType } from '@nestjs/mapped-types';
import { ApiProperty } from '@nestjs/swagger';
import { Status } from '@prisma/client';
import {
  ArrayMinSize,
  IsArray,
  IsIn,
  IsNotEmpty,
  IsString,
  MinLength,
} from 'class-validator';

export class CreatePostDto {
  @ApiProperty()
  @IsArray({ message: 'tag must be an array' })
  @ArrayMinSize(1, { message: 'choose 1 tag at least' })
  @IsIn(
    ['HEALTH', 'BACKEND', 'EDUCATION', 'ENVIRONMENT', 'SCIENCE', 'BUSINESS'],
    { each: true, message: 'Invalid tag' },
  )
  tag: string[];

  @ApiProperty()
  @IsNotEmpty({ message: 'title is required' })
  @IsString({ message: ' title must be in string ' })
  title: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'Body is required for post' })
  @IsString({ message: 'body must be in string only' })
  @MinLength(10, { message: 'post have minimum 10 char long details' })
  body: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'select status' })
  @IsString({ message: 'status is in only string' })
  status: Status;
}

export class UpdatePostDto extends PartialType(CreatePostDto) {}

export class ReviewPostDto {
  @ApiProperty()
  @IsNotEmpty({ message: 'Select status' })
  @IsString({ message: 'Status must be a string' })
  @IsIn(['APPROVED', 'REJECTED'], { message: 'Invalid status' })
  status: Status;
}
