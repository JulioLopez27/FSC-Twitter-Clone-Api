import Router from '@koa/router'
import { PrismaClient } from '@prisma/client'
import bcrypt from "bcrypt"
import jwt from 'jsonwebtoken'

export const router = new Router()
const prisma = new PrismaClient()



router.get('/login', async ctx => {
    // get data[email,pass] encoded base64 from header-authorization
    // split bearer to get TOKEN 
    const [, token] = ctx.request.headers.authorization.split(' ')

    // get values email and password decoded // get data decoded with Buffer
    const [email, plainTextPassword] = Buffer.from(token, 'base64').toString().split(':')

    const user = await prisma.user.findUnique({
        where: { email }
    })
    // error 404 if user is not found
    if (!user) {
        ctx.status = 404
        
        return
    }
    // compare password from token with password saved in DB
    const passwordMatch = bcrypt.compareSync(plainTextPassword, user.password)
    if (passwordMatch) {
        const accessToken = jwt.sign({
            sub: user.id
        }, process.env.JWT_SECRET, { expiresIn: '2h' })
        // remove password
        ctx.body = {
            id: user.id,
            name: user.name,
            username: user.username,
            email: user.email,
            accessToken
        }
        return
    }
    // error 403 if password incorrect
    ctx.status = 403
})


router.post('/signup', async ctx => {
    const saltRounds = 10
    // cripto password
    const HashPassword = bcrypt.hashSync(ctx.request.body.password, saltRounds);
    try {

        // destruct obj user 
        // remove password for comming in the response from server
        const user = await prisma.user.create({
            data: {
                name: ctx.request.body.name,
                username: ctx.request.body.username,
                email: ctx.request.body.email,
                password: HashPassword
            }
        })

        const accessToken = jwt.sign({
            sub: user.id
        }, process.env.JWT_SECRET, { expiresIn: '2h' })

        ctx.body = {
            id: user.id,
            name: user.name,
            username: user.username,
            email: user.email,
            accessToken
        }
    } catch (error) {
        if (error.meta && !error.meta.target) {
            ctx.status = 422
            ctx.body = "Email or username already exist"
            return
        }
        ctx.status = 500
        ctx.body = 'Internal error'
    }
})


// -----------------------------------------------------------------------------------------------------------------


// tweet list from user
router.get('/tweets', async ctx => {

    const [, token] = ctx.request.headers?.authorization?.split(' ') || []
    if (!token) {
        ctx.status = 401
        return
    }
    try {
        jwt.verify(token, process.env.JWT_SECRET)
        const tweets = await prisma.Tweet.findMany({
            //  relaciona el user al tweet al traerme
            // su listado(Join)
            include: {
                user: true
            }
        })
        ctx.body = tweets
    } catch (error) {        
        if (typeof error === 'JsonWebTokenError') {
            ctx.status = 401
            return
        }
        ctx.status = 500
        return
    }
})

// create a new tweet
router.post('/tweets', async ctx => {
    const [, token] = ctx.request.headers?.authorization?.split(' ') || []

    if (!token) {
        console.log("🚀 ~ file: routes.js ~ line 33 ~ token-->", token)
        ctx.status = 401
        return
    }
    try {
        // decoded and verify token and key
        const payload = jwt.verify(token, process.env.JWT_SECRET)
        const tweet = await prisma.tweet.create({
            data: {
                userId: payload.sub,
                text: ctx.request.body.text
            }
        })
        ctx.body = tweet

    } catch (error) {
        console.log("🚀 ~ file: routes.js ~ line 49 ~ error-->", error)
        ctx.status = 401
        return
    }
})