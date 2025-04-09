import pkg from 'jsonwebtoken';
const { sign, verify } = pkg;
import IJwtPayload from "../modules/auth/auth_model.js";
const JWT_SECRET = process.env.JWT_SECRET || "token.010101010101";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "refresh.010101010101";
const ACCES_TOKEN_EXPIRATION="10s";
const REFRESH_TOKEN_EXPIRATION="7d";

//No debemos pasar información sensible en el payload, en este caso vamos a pasar como parametro el ID del usuario
const generateToken = (user:any,additionalData:object={}) => {
    const payload={
        id:user.id,
        name:user.name,
        email:user.email,
        role:user.role||"Admin",
        ...additionalData
    }
    const jwt = sign(payload, JWT_SECRET, {expiresIn: ACCES_TOKEN_EXPIRATION});
    return jwt;
};

const generateRefreshToken = (userId: string): string => {
    const payload = { id: userId, type: 'refresh' } as IJwtPayload;
    return sign(payload, JWT_REFRESH_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRATION });
};


const verifyToken = (jwt: string) => {
    try{
        const isOk = verify(jwt, JWT_SECRET);
        return isOk;
    }catch(error){
        return null;
    }  
};

const verifyRefreshToken=(refreshToken:string)=>{
        return verify(refreshToken, JWT_REFRESH_SECRET);
}

export { generateToken, generateRefreshToken, verifyToken, verifyRefreshToken };