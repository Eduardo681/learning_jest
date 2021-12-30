let app = require('../src/app')
let supertest = require('supertest')
let request = supertest(app)

let mainUser = {
    name: 'Eduardo',
    email: 'edu.slhenrique@gmail.com',
    password: '123546'
}

beforeAll(() => {
    return request.post("/user")
        .send(mainUser)
        .then(res => {
            console.log("Usuário principal cadastrado")
        }).catch(err => {
            console.log(err)
        })
})

afterAll(() => {
    return request.post(`/user/${mainUser.email}`)
        .then(res => {
            console.log("Usuário principal deletado")
        }).catch(err => {
            console.log(err)
        })
})

describe("Cadastro de usuário", () => {
    test("Deve cadastrar um usuário com sucesso", () => {
        let time = Date.now()
        let email = `${time}@gmail.com`
        let user = {
            name: 'Eduardo',
            email,
            password: '123456'
        }
        return request.post("/user")
            .send(user)
            .then(res => {
                let status = res.statusCode
                expect(status).toEqual(200)
                expect(res.body.email).toEqual(email)
            }).catch(err => {
                fail(err)
            })
    })

    test("Deve impedir que um usuário se cadastre com os dados vazios", () => {
        let user = {
            name: '',
            email: '',
            password: ''
        }
        return request.post("/user")
            .send(user)
            .then(res => {
                let status = res.statusCode
                expect(status).toEqual(400)
            }).catch(err => {
                fail(err)
            })
    })

    test("Deve impedir que um usuário se cadastre com um e-mail repetido", () => {
        let time = Date.now()
        let email = `${time}@gmail.com`
        let user = {
            name: 'Eduardo',
            email,
            password: '123456'
        }
        return request.post("/user")
            .send(user)
            .then(res => {
                let status = res.statusCode
                expect(status).toEqual(200)
                expect(res.body.email).toEqual(email)

                return request.post("/user")
                    .send(user)
                    .then((res) => {
                        status = res.statusCode
                        expect(status).toEqual(400)
                        expect(res.body.error).toEqual("E-mail já cadastrado")
                    }).catch((err) => {
                        fail(err)
                    })
            }).catch(err => {
                fail(err)
            })
    })
})

describe("Autenticação", () => {
    test("Deve retornar um token quando logar", () => {
        return request.post("/auth")
            .send({email: mainUser.email, password: mainUser.password})
            .then((res) => {
                expect(res.statusCode).toEqual(200)
                expect(res.body.token).toBeDefined()
            }).catch((err) => {
                fail(err)
            })
    })

    test("Deve impedir que um usuário não cadastrado se logue", () => {
        return request.post("/auth")
            .send({email: "teste@gmail.com", password: mainUser.password})
            .then((res) => {
                expect(res.statusCode).toEqual(403)
                expect(res.body.errors.email).toEqual("E-mail não cadastrado")
            }).catch((err) => {
                fail(err)
            })
    })

    test("Deve impedir que um usuário se logue com a senha errada", () => {
        return request.post("/auth")
            .send({email: mainUser.email, password: "adnasuiodbna"})
            .then((res) => {
                expect(res.statusCode).toEqual(403)
                expect(res.body.errors.password).toEqual("Senha incorreta")
            }).catch((err) => {
                fail(err)
            })
    })
})
