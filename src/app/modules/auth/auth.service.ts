import AppError from "../../errorHelpers/AppError";
import { IUser } from "../user/user.interface";
import httpStatus from "http-status-codes";
import bcrypt from "bcryptjs";
import { User } from "../user/user.model";
import { envVariables } from "../../config/env";
import { generateToken } from "../../utils/jwt";

const credentialsLogin = async (payload: Partial<IUser>) => {
  const { email, password } = payload;

  const isUserExist = await User.findOne({ email });

  if (!isUserExist) {
    throw new AppError(httpStatus.BAD_REQUEST, "User does not exist");
  }

  const isPasswordMatched = await bcrypt.compare(
    password as string,
    isUserExist.password as string
  );

  if (!isPasswordMatched) {
    throw new AppError(httpStatus.BAD_REQUEST, "Incorrect Password");
  }

  const jwtPayload = {
    email: isUserExist.email,
    role: isUserExist.role,
    userId: isUserExist._id,
  };

  const accessToken = generateToken(
    jwtPayload,
    envVariables.JWT_ACCESS_SECRET,
    envVariables.JWT_ACCESS_EXPIRE
  );
  // const accessToken = Jwt.sign(jwtPayload, "secret", {
  //   expiresIn: "1d",
  // });

  return {
    accessToken,
  };
};

export const authServices = {
  credentialsLogin,
};
