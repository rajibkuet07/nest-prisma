import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import * as argon from 'argon2';
import { token } from 'src/common/interfaces';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signUp(dto: AuthDto): Promise<token> {
    // generate the password hash using argon
    const hash = await argon.hash(dto.password);

    // save the new user in the db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      // grant access, send back the jwt token
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credential taken');
        }
      }
      throw error;
    }
  }
  async signIn(dto: AuthDto): Promise<token> {
    // find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if user does not exists throw exception
    if (!user) throw new ForbiddenException('Credential incorrect');

    // compare password
    const pwMatches = await argon.verify(user.hash, dto.password);

    // if password incorrect throw exception
    if (!pwMatches) throw new ForbiddenException('Credential incorrect');

    // grant access, send back the jwt token
    return this.signToken(user.id, user.email);
  }

  async signToken(userId: number, email: string): Promise<token> {
    const payload = {
      sub: userId,
      email,
    };

    return {
      access_token: await this.jwt.signAsync(payload, {
        secret: this.config.get('JWT_SECRET'),
        expiresIn: '15m',
      }),
    };
  }
}
