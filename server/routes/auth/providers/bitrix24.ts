import Router from "koa-router";
import methodOverride from "@server/middlewares/methodOverride";
import { User } from "@server/models";
import { signIn } from "@server/utils/authentication";
import { getUserForBitrixToken } from "@server/utils/jwt";
import { assertPresent } from "@server/validation";

const router = new Router();

export const config = {
  name: "Bitrix24",
  enabled: true,
};

router.use(methodOverride());

router.get("bitrix", async (ctx) => {
  const { bitrix_token } = ctx.request.query;
  console.log(bitrix_token);
  assertPresent(bitrix_token, "token is required");

  let user!: User;

  try {
    user = await getUserForBitrixToken(bitrix_token as string);
  } catch (err) {
    ctx.redirect(
      `https://portal.crm40.ru/outline/?error=token_expaired&url=https://portal.mgtniip.ru:4443/home`
    );
    return;
  }

  await user.update({
    lastActiveAt: new Date(),
  });

  // set cookies on response and redirect to team subdomain
  await signIn(ctx, user, user.team, "email", false, false);
});

export default router;
