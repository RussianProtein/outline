import { subMinutes } from "date-fns";
import JWT from "jsonwebtoken";
import env from "@server/env";
import { Team, User } from "@server/models";
import { AuthenticationError } from "../errors";

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

export async function getUserForBitrixToken(token: string): Promise<User> {
  const payload = getJWTPayload(token);

  // check the token is within it's expiration time
  if (payload.exp) {
    if (new Date(payload.exp * 1000) < subMinutes(new Date(), 10)) {
      throw "exp";
    }
  }

  let condition = { email: payload.email };

  if (payload.type === "session") {
    condition = {
      id: payload.id,
    };
  }

  const user = await User.findOne({
    where: condition,
    include: [
      {
        model: Team,
        required: true,
      },
    ],
  });

  if (!user) {
    throw "notfounduser";
  }

  try {
    JWT.verify(token, env.JWT_SECRET);
  } catch (err) {
    throw AuthenticationError("Invalid token");
  }

  return user;
}
