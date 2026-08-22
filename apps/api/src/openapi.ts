import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import type { OpenAPIObject } from '@nestjs/swagger';

interface JsonResponse {
  json(value: unknown): unknown;
}

export function configureOpenApi(app: INestApplication, enableUi: boolean): OpenAPIObject {
  const options = new DocumentBuilder()
    .setTitle('Kovcheg API')
    .setDescription('Local Alpha-0 technical API surface')
    .setVersion('0.1.0')
    .build();
  const document = SwaggerModule.createDocument(app, options);

  if (enableUi) {
    SwaggerModule.setup('docs', app, document, {
      jsonDocumentUrl: '/openapi.json',
    });
  } else {
    app
      .getHttpAdapter()
      .get('/openapi.json', (_request: unknown, response: JsonResponse) => response.json(document));
  }

  return document;
}
