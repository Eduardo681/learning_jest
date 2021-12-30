let express = require('express')
let app = express()
let mongoose = require('mongoose')
let user = require('./model/User')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let SECRET = 'uheuehuehaodjasdazmdfoal'

app.use(express.urlencoded({extended: false}))
app.use(express.json())

mongoose.connect("mongodb://localhost:27017/guiapics", {useNewUrlParser: true, useUnifiedTopology: true}, null)

let User = mongoose.model('User', user)

app.get("/", (req, res) => {
    res.json({})
})

app.post("/user", async (req, res) => {
    try {
        let {name, email, password} = req.body
        if (name.trim() === '' || email.trim() === '' || password.trim() === '') {
            res.sendStatus(400)
            return;
        }

        let user = await User.findOne({"email": email})
        if (user != undefined) {
            res.status(400)
            res.json({error: "E-mail já cadastrado"})
            return;
        }

        let salt = await bcrypt.genSalt(10)
        let hash = await bcrypt.hash(password, salt)

        let newUser = new User({name, email, password: hash})
        await newUser.save();
        res.json({email: req.body.email})
    } catch (err) {
        console.log(err)
        res.sendStatus(500)
    }
})

app.delete("/user/:email", async (req, res) => {
    try {
        await User.deleteOne({"email": req.params.email})
    } catch (err) {
        console.log(err)
    }
})

app.post("/auth", async (req, res) => {
    try {
        let {email, password} = req.body

        let user = await User.findOne({"email": email})
        if (user === null) {
            res.status(403)
            res.json({errors: {email: "E-mail não cadastrado"}})
            return
        }
        let isPasswordRight = await bcrypt.compare(password, user.password)
        if (!isPasswordRight) {
            res.status(403)
            res.json({errors: {password: "Senha incorreta"}})
            return
        }

        jwt.sign({email, name: user.name, id: user._id}, SECRET, {expiresIn: '48h'}, (err, token) => {
            if (err) {
                console.log(err)
                res.sendStatus(500)
                return
            }
            res.json({token})
        })
    } catch (err) {
        console.log(err)
    }
})

module.exports = app;
