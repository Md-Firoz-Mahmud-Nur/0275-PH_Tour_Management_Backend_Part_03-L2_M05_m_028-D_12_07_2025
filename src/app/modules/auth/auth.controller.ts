import { Request, Response } from "express";
import { catchAsync } from "../../utils/catchAsync";
import { sendResponse } from "../../utils/sendResponse";
import httpStatus from "http-status-codes";
import { authServices } from "./auth.service";
import AppError from "../../errorHelpers/AppError";
import { setAuthCookie } from "../../utils/setCookie";

const credentialsLogin = catchAsync(async (req: Request, res: Response) => {
  const loginInfo = await authServices.credentialsLogin(req.body);

  // res.cookie("accessToken", loginInfo.accessToken, {
  //   httpOnly: true,
  //   secure: false,
  // });

  // res.cookie("refreshToken", loginInfo.refreshToken, {
  //   httpOnly: true,
  //   secure: false,
  // });

  setAuthCookie(res, loginInfo);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.CREATED,
    message: "User Logged In Successfully",
    data: loginInfo,
  });
});

const getNewAccessToken = catchAsync(async (req: Request, res: Response) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    throw new AppError(httpStatus.BAD_REQUEST, "Refresh Token is required");
  }

  const tokenInfo = await authServices.getNewAccessToken(
    refreshToken as string
  );

  // res.cookie("accessToken", tokenInfo.accessToken, {
  //   httpOnly: true,
  //   secure: false,
  // });

  setAuthCookie(res, tokenInfo);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Get New Access Token Successfully",
    data: tokenInfo,
  });
});

export const authControllers = {
  credentialsLogin,
  getNewAccessToken,
};
