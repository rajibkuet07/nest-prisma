import { Body, Controller, Post } from '@nestjs/common';
import { token } from 'src/common/interfaces';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signUp(@Body() dto: AuthDto): Promise<token> {
    return this.authService.signUp(dto);
  }

  @Post('signin')
  signIn(@Body() dto: AuthDto): Promise<token> {
    return this.authService.signIn(dto);
  }
}
