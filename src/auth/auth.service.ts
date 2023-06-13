import { ForbiddenException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import { User } from 'src/user/user.schema';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types/tokens.type';
import { JwtPayload } from 'jsonwebtoken';
import { JwtService } from '@nestjs/jwt';
import { log } from 'console';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('user') private userModel: mongoose.Model<User>,
    private jwtService: JwtService,
  ) {}

  hashData(data: string) {
    const saltNumber = 10;
    return bcrypt.hash(data, saltNumber);
  }

  async getTokens(userId: string, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: 'at-secret',
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: 'rt-secret',
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    const newUser = new this.userModel({ ...dto, hashPw: hash });
    const tokens = await this.getTokens(newUser.id, newUser.email);
    newUser.save();
    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async updateRtHash(userId: string, refresh_token: string) {
    const hashToken = await this.hashData(refresh_token);
    await this.userModel.findByIdAndUpdate(userId, {
      hashedRt: hashToken,
    });
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.userModel.findOne({ email: dto.email });

    if (!user) throw new ForbiddenException('No account with this email');
    const passwordMatches = await bcrypt.compare(dto.password, user.hashPw);
    if (!passwordMatches)
      throw new ForbiddenException('Action denied, Your password is incorrect');

    const tokens = await this.getTokens(user.id, user.email);
    await user.save();
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: string) {
    await this.userModel.updateMany(
      {
        id: userId,
        hashedRt: { $exists: true, $ne: null },
      },
      {
        hashedRt: null,
      },
    );
  }

  async refreshTokens(userId: string, refresh_token: string): Promise<Tokens> {
    const user = await this.userModel.findById(userId);

    if (!user)
      throw new ForbiddenException('Access Denied,User does not exist');

    const rtMatches = await bcrypt.compare(refresh_token, user.hashedRt);

    if (!rtMatches)
      throw new ForbiddenException(
        'Acess denied, You dont have an authorization',
      );

    const tokens = await this.getTokens(user.id, user.email);
    await user.save();
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }
}
