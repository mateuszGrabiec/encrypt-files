import {
  Controller,
  Get,
  Post,
  Req,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  Res,
  StreamableFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { AppService } from './app.service';
import { AuthService } from './auth/auth.service';
import { LocalAuthGuard } from './auth/local-auth.guard';
import { JwtAuthGuard } from './auth/jwt.guard';
import { CryptoService, KeyPair, EncryptedFile } from './crypto/crypto.service';
import 'multer';
import { Readable } from 'stream';

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
  @Post('api/sign-in')
  async login(@Req() req): Promise<any> {
    return this.authService.login(req.body);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req) {
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
  encrypt(
    @UploadedFile() file: Express.Multer.File,
    @Req() req,
  ): EncryptedFile {
    const { pubKey } = req.body;

    const encryptedFile = this.cryptoService.encryptFile(
      file.buffer,
      pubKey.replace(/(\\r\n|\\n|\r)/gm, '\n'),
    );

    return encryptedFile;
  }

  @Post('test/decrypt')
  @UseGuards(JwtAuthGuard)
  decryptTest(@Req() req, @Res({ passthrough: true }) res): StreamableFile {
    const { encryptedKey, privKey, encryptedData, iv } = req.body;

    const decryptedFile = this.cryptoService.decryptFile(
      encryptedKey,
      privKey.replace(/(\\r\n|\\n|\r)/gm, '\n'),
      encryptedData,
      iv,
    );

    res.set({
      'Content-Type': 'application/pdf',
    });

    const file = Readable.from(Buffer.from(decryptedFile, 'base64'));

    return new StreamableFile(file);
  }

  @Post('register')
  async register(@Req() req) {
    const userpost = await this.authService.register(req.body);
    return userpost;
  }
}
