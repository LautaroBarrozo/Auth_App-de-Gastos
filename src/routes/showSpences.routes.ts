import express from "express";
import { Router } from "express";
import { prisma } from '../repository/prisma'
import { User, Spences } from '@prisma/client'
import jwt from "jsonwebtoken";


if(!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET){
    throw new Error("ACCESS TOKEN NOT PRESENT")
}

const secret: string = process.env.ACCESS_TOKEN_SECRET
const refreshSecret: string = process.env.REFRESH_TOKEN_SECRET

const router = Router()

router.get("/show", async (req: express.Request, res: express.Response) =>{

    const header = req.headers.authorization;
    if(!header){
        res.status(401).json({message: "NOT AUTHORIZED: TOKEN NOT PRESENT"});
        return;
    }

    const token = header.split(" ")[1];

    try {
        const data = jwt.verify(token, secret)
        if (data) {
            const dataParsed = data as unknown as User
            
            const user = await prisma().user.findUnique({where:{userEmail: dataParsed.userEmail}})
            
            if(!user){
                throw new Error("USER NOT PRESENT")
            }     

            const userSpences = await prisma().spences.findMany(({where:{userId: user.id}}))

            if (userSpences === null) {
                res.status(404).json({message: "SPENCES NOT FOUND"});
                return;
            }

            if (userSpences.length === 0) {
                res.status(404).json({message: "NO SPENCES FOUND FOR THIS USER"});
                return;
            }

            res.json(userSpences)

            return;
        }
    } catch (err: any) {
        if (err.name === "TokenExpiredError") {
            res.status(401).json({message: "NOT AUTHORIZED: TOKEN EXPIRED"});
            return;
        }

        res.status(401).json({message: "NOT AUTHORIZED: TOKEN NOT VALID"});
        return;
    }
})

export default router