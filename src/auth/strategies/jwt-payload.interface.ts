export interface JwtPayload {
  id: number;
  username: string;
  name: string;
  lastname: string;
  email: string;
  isEmailConfirmed: boolean;
  status: string;
  role: string;
  stripeCustomerId: string;
  isApp?: boolean;
}
