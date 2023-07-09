import express from "express";
import { Router } from "express";
import { prisma } from '../repository/prisma'
import { User, Spences } from '@prisma/client'
import jwt from "jsonwebtoken";

const router = Router()

if(!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET){
    throw new Error("ACCESS TOKEN NOT PRESENT")
}

const secret: string = process.env.ACCESS_TOKEN_SECRET
const refreshSecret: string = process.env.REFRESH_TOKEN_SECRET

router.post("/add", async (req: express.Request, res: express.Response) =>{
    const header = req.headers.authorization;
    

    if(!header){
        res.status(401).json({message: "NOT AUTHORIZED: TOKEN NOT PRESENT"});
        return;
    }

    const token = header.split(" ")[1];

    try {
        const data = jwt.verify(token, secret)
        if (data) {
            const {spenceName, price, userId} = req.body
            const dataParsed = data as unknown as User
            const user = await prisma().user.findUnique({where:{userEmail: dataParsed.userEmail}})

            try {
                if (user === null) {
                    res.status(404).json({message: "USER NOT FOUND"});
                    return;
                }

                if (userId !== user.id) {
                    res.status(400).json({message: "USER ERROR: INCORRECT USER ID"})
                    return;
                }

                const spence = await prisma().spences.create({
                    data:{
                        spenceName: spenceName,
                        price: price,
                        userId: userId
                    }
                })
                res.json(spence)
            } catch (err) {
                res.status(400).json({message: "USER ERROR: CAN'T ADD THIS SPENCE"})
            }

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