import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

export type User = {
  userId: number;
  email: string;
  password: string;
};

@Injectable()
export class UsersService {
  private users: User[];

  constructor() {
    this.users = [
      {
        userId: 1648756857117,
        email: 'example@mail.com',
        password:
          '$2b$10$mskZiUwjipxcmdGectOBL.MEH5LSIsbSYL0ST5jufpK7Hlru6znE6',
      },
      {
        userId: 1648756766407,
        email: 'test@mail.com',
        password:
          '$2b$10$wClwEUcBHSpwSTZHnrbH/O1l2WhtVsu1MArrtP6qWG7ae8Qzadjle',
      },
    ];
  }

  async findOne(email: string): Promise<User | undefined> {
    return this.users.find((user) => user.email === email);
  }

  async create(userData: any): Promise<any> {
    const salt = await bcrypt.genSalt(10);

    const hashedPassword = await bcrypt.hash(userData.password, salt);
    const userId = Date.now();

    this.users.push({
      userId: userId,
      email: userData.email,
      password: hashedPassword,
    });

    return {
      userId: userId,
      email: userData.email,
      password: hashedPassword,
    };
  }
}
