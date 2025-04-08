import { BadRequestException, Injectable } from '@nestjs/common';
import { SignupDto } from './dto/sign-up.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {

  constructor(private prisma: PrismaService,
              private jwtService: JwtService,
  ) {}

  async signup(dto: SignupDto) {
    // check if alr there or not
    const existing = await this.prisma.user.findUnique({
      where: {email: dto.email},
    });
    if (existing) throw new BadRequestException("Email is already in used");
    const password = await bcrypt.hash(dto.password, 10)
    
    // create user
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: password
      },
    });
    // sign jwt
    return this.signToken(user.id, user.email);
  }

  async signToken(userId: string, email: string) {
    const payload = {
      sub: userId,
      email: email,
    }
    const token = await this.jwtService.signAsync(payload);
    return {
      access_token: token,
    };
  }

  login(dto: LoginDto) {

  }
}
