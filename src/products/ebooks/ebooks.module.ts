import { Module } from '@nestjs/common';
import { EbooksController } from './ebooks.controller';
import { EbooksService } from './ebooks.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Product } from 'src/entities/product.entity';
import { Files } from 'src/entities/files.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Product, Files])], // Add Product and File to use repository in service.],
  controllers: [EbooksController],
  providers: [EbooksService],
})
export class EbooksModule {}
