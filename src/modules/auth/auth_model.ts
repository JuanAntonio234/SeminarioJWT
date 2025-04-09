export interface Auth {
    name:string;
    email:string;
    password:string;
    googleId?: string; 
}
export default interface IJwtPayload {
    id: string;
    type: 'access' | 'refresh';
}