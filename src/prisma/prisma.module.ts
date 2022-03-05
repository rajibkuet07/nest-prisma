import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Global() // make it global so that each module can access this
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
