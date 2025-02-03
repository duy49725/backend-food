import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/user';
import { auth } from 'express-oauth2-jwt-bearer';

declare global {
    namespace Express {
        interface Request {
            userId?: string;
            auth0Id?: string;
        }
    }
}

export const jwtCheck = auth({
  audience: 'mern-food-app',
  issuerBaseURL: 'https://dev-7iddfobtvj5bvuj0.us.auth0.com/',
  tokenSigningAlg: 'RS256'
});

export const jwtParse = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const { authorization } = req.headers;
        if (!authorization || !authorization.startsWith("Bearer ")) {
            res.status(401).json({ message: "Unauthorized" });
            return;
        }

        const token = authorization.split(" ")[1];
        const decoded = jwt.decode(token) as jwt.JwtPayload | null;

        if (!decoded || !decoded.sub) {
            res.status(401).json({ message: "Invalid token" });
            return;
        }

        const auth0Id = decoded.sub;
        const user = await User.findOne({ auth0Id });

        if (!user) {
            res.status(401).json({ message: "User not found" });
            return;
        }

        req.auth0Id = auth0Id as string;
        req.userId = user._id.toString();

        await next();
        return;
    } catch (error) {
        res.status(500).json({ message: "Internal server error" });
        return;
    }
};
