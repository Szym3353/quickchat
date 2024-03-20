import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { Model } from 'mongoose';
import { User } from 'src/schemas/user.schema';
import bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

export class SignInDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}

export class SignUpDto extends SignInDto {
  @IsNotEmpty()
  @IsString()
  confirmPassword: string;

  @IsNotEmpty()
  @IsString()
  username: string;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async signIn({ email, password }: SignInDto) {
    let user = await this.userModel.findOne({ email });
    if (!user)
      throw new HttpException('Incorrect credentials', HttpStatus.FORBIDDEN);

    let compare = bcrypt.compare(password, user.password);
    if (!compare)
      throw new HttpException('Incorrect credentials', HttpStatus.FORBIDDEN);

    return {
      access_token: await this.jwtService.signAsync({ sub: user._id }),
    };
  }

  async singUp({ email, username, password, confirmPassword }) {
    let exists = await this.userModel.exists({ email });
    if (exists)
      throw new HttpException('User already exists', HttpStatus.FORBIDDEN, {
        cause: 'email',
      });

    if (confirmPassword !== password)
      throw new HttpException(
        'Passwords does not match',
        HttpStatus.FORBIDDEN,
        { cause: 'confirmPassword' },
      );

    let hashedPassword = await bcrypt.hash(password, 12);

    let newUserData = { username, email, password: hashedPassword };

    let newUser = await this.userModel.create(newUserData);

    return {
      access_token: await this.jwtService.signAsync({ sub: newUser._id }),
    };
  }
}
