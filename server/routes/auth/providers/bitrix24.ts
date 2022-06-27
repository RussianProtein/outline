import Router from "koa-router";
import env from "@server/env";
import methodOverride from "@server/middlewares/methodOverride";
import { User } from "@server/models";
import { signIn } from "@server/utils/authentication";
import { getUserForBitrixToken } from "@server/utils/jwtBitrix";
import { assertPresent } from "@server/validation";

const router = new Router();

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
      ctx.redirect(env.USER_NOT_FOUND + ctx.request.href);
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

export default router;
