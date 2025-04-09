import { encrypt, verified } from "../../utils/bcrypt.handle.js";
import { generateToken,generateRefreshToken, verifyToken, verifyRefreshToken } from "../../utils/jwt.handle.js";
import User, { IUser } from "../users/user_models.js";
import { Auth } from "./auth_model.js";
import axios from 'axios';

const registerNewUser = async ({ email, password, name, age }: IUser) => {
    const checkIs = await User.findOne({ email });
    if(checkIs) return "ALREADY_USER";
    const passHash = await encrypt(password);
    const registerNewUser = await User.create({ 
        email, 
        password: passHash, 
        name, 
        age });
    return registerNewUser;
};

const loginUser = async ({ email, password }: Auth) => {
    const checkIs = await User.findOne({ email });
    if(!checkIs) return "NOT_FOUND_USER";
    
    const passwordHash = checkIs.password; //El encriptado que viene de la bbdd
    const isCorrect = await verified(password, passwordHash);
    if(!isCorrect) return "INCORRECT_PASSWORD";

    const token = generateToken(checkIs);
    const refreshToken=generateRefreshToken(checkIs.id);
    checkIs.refreshToken=refreshToken;
    await checkIs.save();

    return {
        token,
        refreshToken,
        checkIs
    }
};


const googleAuth = async (code: string) => {

    try {
        console.log("Client ID:", process.env.GOOGLE_CLIENT_ID);
        console.log("Client Secret:", process.env.GOOGLE_CLIENT_SECRET);
        console.log("Redirect URI:", process.env.GOOGLE_OAUTH_REDIRECT_URL);
    
        if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_OAUTH_REDIRECT_URL) {
            throw new Error("Variables de entorno faltantes");
        }

        interface TokenResponse {
            access_token: string;
            expires_in: number;
            scope: string;
            token_type: string;
            id_token?: string;
        }

        const tokenResponse = await axios.post<TokenResponse>('https://oauth2.googleapis.com/token', {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL,
            grant_type: 'authorization_code'
        });

        const access_token = tokenResponse.data.access_token;
        console.log("Access Token:", access_token); 
        // Obtiene el perfil del usuario
        const profileResponse = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
            params: { access_token},
            headers: { Accept: 'application/json',},
            
        });

        const profile = profileResponse.data as {name:string, email: string; id: string };
        console.log("Access profile:", profile); 
        // Busca o crea el usuario en la base de datos
        let user = await User.findOne({ 
            $or: [{name: profile.name},{ email: profile.email }, { googleId: profile.id }] 
        });

        if (!user) {
            const randomPassword = Math.random().toString(36).slice(-8);
            const passHash = await encrypt(randomPassword);
            user = await User.create({
                name: profile.name,
                email: profile.email,
                googleId: profile.id,
                password: passHash,
            });
        }

        // Genera el token JWT
        const token = generateToken(user);
        const refreshToken=generateRefreshToken(user.id);

        user.refreshToken=refreshToken;
        await user.save();

        console.log(token);
        return { token, refreshToken, user };

    } catch (error: any) {
        console.error('Google Auth Error:', error.response?.data || error.message); // Log detallado
        throw new Error('Error en autenticación con Google');
    }
};

const refreshAccessToken = async (refreshToken: string) => {
    try {
        const decoded: any = verifyRefreshToken(refreshToken); 
        if (!decoded || !decoded.id) {
            throw new Error("Token no válido");
        }

        const user = await User.findById(decoded.id);

        if (!user || user.refreshToken !== refreshToken) {
            throw new Error("Refresh token inválido");
        }

        return generateToken(user); 

    } catch (error: any) {
        throw new Error("No se pudo refrescar el token");
    }
};


export { registerNewUser, loginUser, googleAuth,refreshAccessToken};