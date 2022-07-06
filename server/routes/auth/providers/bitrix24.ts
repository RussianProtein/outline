import JWT from "jsonwebtoken";
import Router from "koa-router";
import accountProvisioner from "@server/commands/accountProvisioner";
import env from "@server/env";
import methodOverride from "@server/middlewares/methodOverride";
import { User } from "@server/models";
import { signIn } from "@server/utils/authentication";
import { getUserForBitrixToken } from "@server/utils/jwtBitrix";
import { assertPresent } from "@server/validation";
import { AuthenticationError } from "../../../errors";

const router = new Router();

const scopes = [];

export const config = {
  name: "Bitrix24",
  enabled: true,
};

router.use(methodOverride());

router.get("bitrix", async (ctx) => {
  const { bitrix_token } = ctx.request.query;

  assertPresent(bitrix_token, "token is required");

  let user!: User;

  try {
    user = await getUserForBitrixToken(bitrix_token as string);
  } catch (err) {
    if (err === "exp") {
      ctx.redirect(env.TOKEN_EXPAIRED + ctx.request.href);
    } else if (err === "notfounduser") {
      const profile = getJWTPayload(bitrix_token as string);

      const domain = profile.email.split("@")[1];
      const diplayName = profile.email.split("@")[0];
      const subdomain = domain.split(".")[0];
      const teamName = env.TEAM_NAME;
      const providerName = env.PROVIDER_NAME;
      const provirderId = env.PROVIDER_ID;

      await accountProvisioner({
        ip: ctx.request.ip,
        team: {
          name: teamName,
          domain,
          subdomain,
        },
        user: {
          name: diplayName,
          email: profile.email.toLowerCase(),
        },
        authenticationProvider: {
          name: providerName,
          providerId: domain,
        },
        authentication: {
          providerId: provirderId,
          // @ts-expect-error ts-migrate(7005) FIXME: Variable 'scopes' implicitly has an 'any[]' type.
          scopes: scopes,
        },
      });

      user = await getUserForBitrixToken(bitrix_token as string);

      await signIn(ctx, user, user.team, "email", false, false);
    } else {
      ctx.redirect(env.TOKEN_EXPAIRED + ctx.request.href);
    }
    return;
  }

  await user.update({
    lastActiveAt: new Date(),
  });

  // set cookies on response and redirect to team subdomain
  await signIn(ctx, user, user.team, "email", false, false);
});

function getJWTPayload(token: string) {
  let payload;

  try {
    payload = JWT.decode(token);

    if (!payload) {
      throw AuthenticationError("Invalid token");
    }

    return payload as JWT.JwtPayload;
  } catch (err) {
    throw AuthenticationError("Unable to decode JWT token");
  }
}

export default router;
