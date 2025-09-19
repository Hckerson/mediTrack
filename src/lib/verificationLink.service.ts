import { genToken } from './gen-token';
import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class VerificationLink {
  private token: string;
  constructor(private readonly prisma: PrismaService) {}

  async generateVerificationLink(email: string) {
    // generate verification link and store in database
    this.token = genToken();
    await this.storeVerificationToken(email);
    return `http://localhost:3001/verify?email=${email}&token=${this.token}`;
  }

  async storeVerificationToken(email: string) {
    // function to store verification token in database
    const user = await this.prisma.user.update({
      where: {
        email: email.toLowerCase(),
      },
      data: {
        verificationToken: this.token as string,
      },
    });
  }
}
