import { ExecutionContext, Injectable, Logger } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
export class OidcAuthGuard extends AuthGuard("oidc") {
  constructor(private referer: Record<string, string>) {
    referer = {};
    super();
  }

  getRequest(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    if (!request.headers["cookie"]){
      Logger.warn("No cookies found. This indicates that the express session is not configured. Have you set EXPRESS_SESSION_SECRET environment variable?")
      return request;
    }
    
    const cookie: string = request.headers["cookie"]
      .split(";")
      .find((c: string) => c.startsWith("connect.sid="));
    if (request.headers["referer"]) {
      this.referer[cookie] = request.headers["referer"];
    } else {
      request.headers["referer"] = this.referer[cookie];
      delete this.referer[cookie];
    }
    return request;
  }
}
