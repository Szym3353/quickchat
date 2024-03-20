import { Body, Controller, Post, ValidationPipe } from '@nestjs/common';
import { AuthService, SignInDto, SignUpDto } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/login')
  async login(@Body(new ValidationPipe()) signInDto: SignInDto) {
    return await this.authService.signIn(signInDto);
  }

  @Post('/register')
  async register(@Body(new ValidationPipe()) singUpDto: SignUpDto) {
    return await this.authService.singUp(singUpDto);
  }
}
