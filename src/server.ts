import express, { Request, Response } from 'express'
import bodyParser from 'body-parser'
//import routes from './routes'
import articleRoutes from './handlers/article'
const app: express.Application = express()
const address: string = "localhost:3000"

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

app.get('/', function (req: Request, res: Response) {
    res.send('Hello World!')
})

articleRoutes(app)

app.listen(3000, function () {
    console.log(`starting app on: ${address}`)
})
