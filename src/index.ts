import express, { json } from 'express'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import { prisma } from './repository/prisma'
import { User } from '@prisma/client'
import showSpences from "./routes/showSpences.routes"
import addSpences from "./routes/addSpences.routes"

const PORT = process.env.PORT || 3000

const app = express()
if(!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET){
    throw new Error("ACCESS TOKEN NOT PRESENT")
}

const secret: string = process.env.ACCESS_TOKEN_SECRET
const refreshSecret: string = process.env.REFRESH_TOKEN_SECRET

app.use(express.json())

app.post("/register", async (req: express.Request, res: express.Response) => {
    const {userName, userEmail, userPassword} = req.body

    const hash = await bcrypt.hash(userPassword, 10)
        

    try {
        const checkUser = await prisma().user.findUnique({where: {userEmail: userEmail}})

        if (checkUser) {
            res.status(400).json({message: "USER ERROR: THERE IS ALREADY AN ACCOUNT USING THIS EMAIL"})
            return
        }

        const user = await prisma().user.create({
            data:{
                userName: userName,
                userEmail: userEmail,
                userPassword: hash
            }
        })
        res.json(user)
    } catch (err) {
        res.status(400).json({message: "USER ERROR: THERE IS ALREADY AN ACCOUNT USING THIS EMAIL"})
    }


})

app.get("/login", async(req: express.Request, res: express.Response) => {
    const {userName, userEmail, userPassword} = req.body

    try {
        const user = await prisma().user.findUnique({where: {userEmail: userEmail}})

        if (user === null) {
            res.status(404).json({message: "USER NOT FOUND"});
            return;
        }

        if (user.userName !== userName) {
            res.status(401).json({message: "INVALID USER NAME"});
            return;
        }

        const result = await bcrypt.compare(userPassword, user.userPassword)

        if (result) {
            const accessToken = jwt.sign({userName: userName ,userEmail: userEmail}, secret, {expiresIn: '1h'})
            const refreshToken = jwt.sign({userName: userName ,userEmail: userEmail}, refreshSecret, {expiresIn: '72h'})
            res.json({access_token: accessToken, refresh_Token: refreshToken})
            res.send(result)
        }

        res.status(401).send({message: "INVALID PASSWORD"});
        return;
        
    } catch (err) {
        res.status(400).json({message: "USER ERROR"})
    }
    
})

app.post("/refresh", async (req: express.Request, res: express.Response) =>{

    const header = req.headers.authorization
    if (!header) {
        res.status(401).json({message: "NOT AUTHORIZED: TOKEN NOT PRESENT"});
        return;
    }

    const token = header.split(" ")[1]
    try {
        const data = jwt.verify(token, refreshSecret)
        if (data) {
            const dataParsed = data as unknown as User

            const user = await prisma().user.findUnique({where:{userEmail: dataParsed.userEmail}})

            if (user === null) {
                res.status(404).json({message: "USER NOT FOUND"});
                return;
            }

            const accessToken = jwt.sign({userName: user.userName ,userEmail: user.userEmail}, secret, {expiresIn: '1h'})
            const refreshToken = jwt.sign({userName: user.userName ,userEmail: user.userEmail}, refreshSecret, {expiresIn: '72h'})

            res.json({access_token: accessToken, refreshToken: refreshToken})
            return;
        }
    } catch (err: any) {
        if (err.name === 'TokenExpiredError') {
            res.status(401).json({message: 'NOT AUTHORIZED: TOKEN EXPIRED'})
            return;
        }
        res.status(401).json({message: "NOT AUTHORIZED: TOKEN NOT VALID"});
        return;
    }

    res.status(401).json({message: "NOT AUTHORIZED: TOKEN NOT VALID"});
    return;
})

app.use("/main", showSpences)
app.use("/main", addSpences)

app.get("/", (req: express.Request, res: express.Response) => {
    res.writeHead(200, {'content-type': 'text/html'})
    res.write("Usando POST y la ruta /register podras crear un usuario\n")
    res.write("Usando GET y la ruta /login podras conseguir un token y un refresh token\n")
    res.write("Usando POST y la ruta /refres podras conseguir un nuevos token y un refresh token\n")
    res.write("Usando POST y la ruta /main/add podras añadir un gasto colocando el token y los datos solicitados\n")
    res.write("Usando GET y la ruta /main/show podras ver los gastos de un usuario colocando su token\n")
    res.send()
})


app.listen(PORT, () => {
    console.log("Server running on port 3000");
})