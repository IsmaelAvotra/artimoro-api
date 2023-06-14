import { AuthGuard } from '@nestjs/passport';

export class AcessTokensGuards extends AuthGuard('jwt') {
  constructor() {
    super();
  }
}
