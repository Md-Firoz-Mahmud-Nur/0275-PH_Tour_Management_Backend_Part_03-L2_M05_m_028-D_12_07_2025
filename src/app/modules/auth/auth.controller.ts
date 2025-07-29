import { Request, Response } from "express";
import { catchAsync } from "../../utils/catchAsync";
import { sendResponse } from "../../utils/sendResponse";
import httpStatus from "http-status-codes";
import { authServices } from "./auth.service";


const credentialsLogin = catchAsync(async (req: Request, res: Response) => {
const loginInfo = await authServices.credentialsLogin(req.body);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.CREATED,
    message: "User Logged In Successfully",
    data: loginInfo,
  });
});

export const authControllers = {
  credentialsLogin,
};
