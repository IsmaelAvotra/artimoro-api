import { AuthGuard } from '@nestjs/passport';

export class RefreshTokensGuards extends AuthGuard('jwt-refresh') {
  constructor() {
    super();
  }
}
