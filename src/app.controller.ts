import {
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { AppService } from './app.service';
import { AuthService } from './auth/auth.service';
import { LocalAuthGuard } from './auth/local-auth.guard';
import { JwtAuthGuard } from './auth/jwt.guard';
import { CryptoService, KeyPair } from './crypto/crypto.service';
import 'multer';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly authService: AuthService,
    private readonly cryptoService: CryptoService,
  ) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @UseGuards(LocalAuthGuard)
  @Post('auth/login')
  async login(@Request() req) {
    return this.authService.login(req.body);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }

  @UseGuards(JwtAuthGuard)
  @Post('api/generate-key-pair')
  getKeys(): KeyPair {
    return this.cryptoService.generateKeyPair();
  }

  @UseGuards(JwtAuthGuard)
  @Post('api/encrypt')
  @UseInterceptors(FileInterceptor('file'))
  encrypt(@UploadedFile() file: Express.Multer.File, @Request() req): string {
    const { privKey, pubKey } = req.body;

    const encryptedFile = this.cryptoService.encryptFile(
      file.buffer,
      pubKey.replace(/(\\r\n|\\n|\r)/gm, '\n'),
      privKey.replace(/(\\r\n|\\n|\r)/gm, '\n'),
    );

    return encryptedFile;
  }

  @Post('test/encrypt')
  @UseInterceptors(FileInterceptor('file'))
  encryptTest(
    @UploadedFile() file: Express.Multer.File,
    @Request() req,
  ): string {
    const { privKey, pubKey } = req.body;

    const encryptedFile = this.cryptoService.encryptFile(
      file.buffer,
      pubKey.replace(/(\\r\n|\\n|\r)/gm, '\n'),
      privKey.replace(/(\\r\n|\\n|\r)/gm, '\n'),
    );

    return encryptedFile;
  }

  @Post('register')
  async register(@Request() req) {
    const userpost = await this.authService.register(req.body);
    return userpost;
  }
}
