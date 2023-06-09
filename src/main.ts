import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as session from 'express-session';
import { AppModule } from './app.module';
import * as sgMail from '@sendgrid/mail';

sgMail.setApiKey(
  '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',
);
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(
    session({
      secret: 'secret',
      resave: false,
      saveUninitialized: false,
    }),
  );

  app.useGlobalPipes(new ValidationPipe());

  const config = new DocumentBuilder()
    .addBearerAuth()
    .setTitle('SAHIL')
    .setDescription('Implement by me')
    .setVersion('mdl')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  await app.listen(3000);
}
bootstrap();
