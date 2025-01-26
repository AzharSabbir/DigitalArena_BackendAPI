import {
  BadRequestException,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compare } from 'bcrypt';
import { UsersService } from 'src/users/users.service';
import { AuthJwtPayload } from './types/auth-jwtPayload';
import refreshJwtConfig from './config/refresh-jwt.config';
import { ConfigType } from '@nestjs/config';
import * as argon2 from 'argon2';
import { CurrentUser } from './types/current-user';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { nanoid } from 'nanoid';
import { Verification } from 'src/entities/verification.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VerificationType } from './enums/verification-type.enum';
import { MailService } from './services/mail.service';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerificationMethod } from './enums/verification-method.enum';
import { SmsService } from './services/sms.service';
import { generateOtp } from './utility/otp.util';
import { maskEmail } from './utility/email-mask.util';
import { ActionType } from './enums/action-type.enum';
import { ActionLogsService } from 'src/action-logs/action-logs.service';

@Injectable()
export class AuthService {
  constructor(
    private actionLogsService: ActionLogsService,
    private userService: UsersService,
    private jwtService: JwtService,
    private mailService: MailService,
    private smsService: SmsService,
    @Inject(refreshJwtConfig.KEY)
    private refreshTokenConfig: ConfigType<typeof refreshJwtConfig>,
    @InjectRepository(Verification)
    private verificationRepository: Repository<Verification>,
  ) {}

  async validateUser(identifier: string, password: string) {
    const user = await this.userService.getUserByDynamicCredential(identifier);

    if (!user)
      throw new UnauthorizedException(`User for ${identifier} not found`);

    const isPasswordValid = await compare(password, user.password);

    if (!isPasswordValid)
      throw new UnauthorizedException('Invalid Credentials');

    return { id: user.id };
  }

  async login(userId: number) {
    const { accessToken, refreshToken } = await this.generateTokens(userId);

    const hashedRefreshToken = await argon2.hash(refreshToken);
    await this.userService.updateHashedRefreshToken(userId, hashedRefreshToken);

    this.userService.updateLastLogin(userId); // Update last login date

    // Update Action Log
    const actionLog = {
      action: ActionType.USER_LOGIN,
      description: 'User logged in',
      user: await this.userService.getUserProfileInfo(userId),
    };
    await this.actionLogsService.createActionLog(actionLog);

    const accessTokenExpiresIn = Date.now() + 1000 * 60 * 60 * 24; // 1 day

    return {
      id: userId,
      accessToken,
      refreshToken,
      accessTokenExpiresIn,
    };
  }

  async generateTokens(id: number) {
    const payload: AuthJwtPayload = { sub: id };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload),
      this.jwtService.signAsync(payload, this.refreshTokenConfig),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(userId: number) {
    const { accessToken, refreshToken } = await this.generateTokens(userId);

    const hashedRefreshToken = await argon2.hash(refreshToken);
    await this.userService.updateHashedRefreshToken(userId, hashedRefreshToken);

    const accessTokenExpiresIn = Date.now() + 1000 * 60 * 60 * 24; // 1 day

    return {
      id: userId,
      accessToken,
      refreshToken,
      accessTokenExpiresIn,
    };
  }

  async validateRefreshToken(userId: number, refreshToken: string) {
    const user = await this.userService.getUserRefreshTokenFromDB(userId);

    if (!user || !user.refreshToken)
      throw new UnauthorizedException(`Invalid refresh token`);

    const isRefreshTokenMatching = await argon2.verify(
      user.refreshToken,
      refreshToken,
    );

    if (!isRefreshTokenMatching)
      throw new UnauthorizedException('Invalid Refresh Token');

    return { id: user.id };
  }

  async logout(userId: number) {
    // Update Action Log
    const actionLog = {
      action: ActionType.USER_LOGOUT,
      description: 'User logged out',
      user: await this.userService.getUserProfileInfo(userId),
    };
    await this.actionLogsService.createActionLog(actionLog);

    return await this.userService.updateHashedRefreshToken(userId, null);
  }

  async validateJwtUser(userId: number) {
    const user = await this.userService.getUserProfileInfo(userId);

    if (!user) throw new UnauthorizedException(`User not found`);

    const currentUser: CurrentUser = {
      id: user.id,
      role: user.role,
    };
    return currentUser;
  }

  async validateGoogleUser(googleUser: CreateUserDto) {
    const user = await this.userService.getUserByEmail(googleUser.email);

    if (user) return user;

    return await this.userService.createUser(googleUser);
  }

  /////////////////////////////// Change User Password ///////////////////////////////
  async changePassword(id: number, changePasswordDto: ChangePasswordDto) {
    const user = await this.userService.getUserByIdWithCredential(id);
    if (!user) {
      throw new NotFoundException(`User not found`);
    }

    if (!(await compare(changePasswordDto.oldPassword, user.password))) {
      throw new UnauthorizedException('Old password does not match');
    }

    if (changePasswordDto.oldPassword === changePasswordDto.newPassword) {
      throw new BadRequestException(
        'New password cannot be same as old password',
      );
    }

    const hashedPassword = bcrypt.hashSync(changePasswordDto.newPassword, 10);
    const result = this.userService.changePassword(id, hashedPassword);

    // Update Action Log
    const actionLog = {
      action: ActionType.USER_CHANGE_PASSWORD,
      description: 'User Changed Password',
      user: user,
    };
    await this.actionLogsService.createActionLog(actionLog);

    return {
      message: 'Password changed successfully',
      generatedMaps: (await result).generatedMaps,
      raw: (await result).raw,
      affected: (await result).affected,
    };
  }

  /////////////////////////////// Forgot Password ///////////////////////////////
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const user = await this.userService.getUserByDynamicCredential(
      forgotPasswordDto.identifier,
    );
    if (!user) {
      throw new NotFoundException(`User not found`);
    }

    /////////////////// Verification Method: EMAIL

    if (forgotPasswordDto.verificationMethod === VerificationMethod.EMAIL) {
      const resetToken = nanoid(64);
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1); // Expires in 1 hour

      // Check if user has same type of verification data saved in database. If yes, then delete it.
      await this.verificationRepository.delete({
        type: VerificationType.PASSWORD_RESET_TOKEN,
        userId: user.id,
      });

      const verificationData = this.verificationRepository.create({
        type: VerificationType.PASSWORD_RESET_TOKEN,
        tokenOrOtp: resetToken,
        user: user,
        expiresAt: expiresAt,
      });
      await this.verificationRepository.save(verificationData);

      const response = await this.mailService.sendPasswordResetEmail(
        user.email,
        user.fullName,
        resetToken,
      );

      const maskedEmail = maskEmail(user.email);
      if (response.accepted.length > 0 && response.rejected.length === 0) {
        return {
          message: `Password reset link sent to your email ${maskedEmail}`,
          resetToken: resetToken,
        };
      } else {
        return {
          message: `Failed to sent email to your email ${maskedEmail}`,
        };
      }
    }

    /////////////////// Verification Method: SMS
    else if (forgotPasswordDto.verificationMethod === VerificationMethod.SMS) {
      const otp = generateOtp();
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + 2); // Expires in 2 minutes

      // Check if user has same type of verification data saved in database. If yes, then delete it.
      await this.verificationRepository.delete({
        type: VerificationType.PASSWORD_RESET_OTP,
        userId: user.id,
      });

      // Save new OTP verification data
      const verificationData = this.verificationRepository.create({
        type: VerificationType.PASSWORD_RESET_OTP,
        tokenOrOtp: otp,
        user: user,
        expiresAt: expiresAt,
      });
      await this.verificationRepository.save(verificationData);

      // If phone number is null or empty or undefined then throw error
      if (!user.phone) {
        throw new BadRequestException('Phone number not found');
      }
      const response = await this.smsService.sendOtp(
        user.phone,
        otp,
        user.fullName,
      ); // Send OTP to user phone

      const maskedPhone = `********${user.phone.slice(-3)}`;

      if (response.success) {
        return {
          message: `OTP Successfully sent to your phone number ${maskedPhone}`,
        };
      } else {
        return {
          message: `Failed to send OTP to your phone number ${maskedPhone}`,
        };
      }
    } else {
      throw new BadRequestException('Invalid verification method');
    }
  }

  /////////////////////////////// Reset Password ///////////////////////////////
  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    // Verification Method: EMAIL
    if (resetPasswordDto.verificationMethod === VerificationMethod.EMAIL) {
      const verificationObj = await this.verificationRepository.findOne({
        where: {
          tokenOrOtp: resetPasswordDto.resetTokenOrOTP,
          type: VerificationType.PASSWORD_RESET_TOKEN,
        },
        relations: ['user'], // It will include user object in the response. Access by verificationObj.user
      });

      if (!verificationObj) {
        throw new UnauthorizedException('Password Reset Link Expired');
      }

      const user = verificationObj.user;
      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (verificationObj.expiresAt < new Date()) {
        throw new BadRequestException('Password reset Link expired');
      }

      const hashedPassword = bcrypt.hashSync(resetPasswordDto.newPassword, 10);
      await this.userService.changePassword(user.id, hashedPassword);

      await this.verificationRepository.delete(verificationObj.id);

      // Update Action Log
      const actionLog = {
        action: ActionType.USER_CHANGE_PASSWORD,
        description: 'User Reset Password With EMAIL Verification',
        user: user,
      };
      await this.actionLogsService.createActionLog(actionLog);

      return { message: 'Password reset successful' };
    }

    // Verification Method: SMS
    else if (resetPasswordDto.verificationMethod === VerificationMethod.SMS) {
      const verificationObj = await this.verificationRepository.findOne({
        where: {
          tokenOrOtp: resetPasswordDto.resetTokenOrOTP,
          type: VerificationType.PASSWORD_RESET_OTP,
        },
        relations: ['user'], // It will include user object in the response. Access by verificationObj.user
      });

      if (!verificationObj) {
        throw new UnauthorizedException('Invalid or Expired OTP');
      }

      const user = verificationObj.user;
      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (verificationObj.expiresAt < new Date()) {
        throw new BadRequestException('OTP expired');
      }

      const hashedPassword = bcrypt.hashSync(resetPasswordDto.newPassword, 10);
      await this.userService.changePassword(user.id, hashedPassword);

      await this.verificationRepository.delete(verificationObj.id);

      // Update Action Log
      const actionLog = {
        action: ActionType.USER_CHANGE_PASSWORD,
        description: 'User Reset Password With SMS Verification',
        user: user,
      };
      await this.actionLogsService.createActionLog(actionLog);

      return { message: 'Password reset successful' };
    } else {
      throw new BadRequestException('Invalid verification method');
    }
  }
}
