# Lesson 5 Authentication and Autorization
## Lesson 1-Introduction and lesson overview
## Course Progress
Highlight Authentication and Security in a Node API
You are here: Authentication and Security/Authorization in a Node API
## What we'll do
This lesson is all about security. We need to protect information in our database and handle things like user authenticaion. We'll cover the following topics
- Password hashing and salt
- Implementing the bcrypt library for password hashing
- Introduction to JWT's
- Implementing JWTs with the library json-web-token
## Helpful Preparation
To get ready for this lesson, and hopefully drum up some curiosity, you can [visit jwt.io](https://jwt.io/) to view their excellent docs and introduction to JWTs.

-------------------------------------------
## 2-Database Security - SALT and password hashing
## Database Security
We have learned how to store data in a Postgres database, but there are a few topics we haven’t covered. One of the big concepts we’ve side stepped up to this point is data security. When we’re storing information like worlds, plants, or weapons, none of that information is sensitive. If someone got access to our database they could make a mess but the bad things they could do with that information are limited. Other tables though, for example a users table, have information that needs to be protected like passwords, IDs, even emails or credit card information - there are lots of data points that an attacker could use maliciously if they got a hold of it. This section introduces the important concepts behind protecting passwords in a database.
Remaining Time -0:00
1x
## Video Summary
- A hashed password has been run through a function that generates a long encrypted string from the original password.
- The same password run through the same hash function will generate the same response, this is how we can match passwords when users log in
- Simply hashing passwords though isn't enough, adding Salt, an extra string sequence to the beginning or end of a password before hashing it makes it much harder for attackers to decrypt passwords
- Bcrypt is a very common library for password hashing in web apps

## Fun Extra -- What does Salt mean anyway?
I always thought that Salt was one of the million tech acronyms, but it isn't! In fact, there's some debate about how we even came to use the word salt for this process. Some say it is a reference to ancient war and salting fields to make them unusable, others say we use the word salt because it is an additive put on food that changes it. This argument is strengthened by the process of salt and peppering, which is yet another layer we can add to password hashes to make sure they are harder to unravel in case of a break in.

Here is an interesting stack overflow thread discussing the various possible etymologies for the word salt in cryptography. https://stackoverflow.com/questions/244903/why-is-a-password-salt-called-a-salt

-------------------------------------------------------------

## 3-Password hash creation and validation with Bcrypt
## Installing Bcrypt

In the last section I introduced you to the concepts of password hashing and salt. Bcrypt is a very common library for implementing password encryption and in this section I'm going to walk you through password protection and validation in a Node API.
Steps to install Bcrypt
## Task List
- Add the dependency: <code>yarn add bcrypt</code>
- Import bcrypt into the user model:
<code>import bcrypt from 'bcrypt'</code>
- Create the necessary environment variables:
<code>BCRYPT_PASSWORD=your-secret-password
SALT_ROUNDS=10</code>
- Use the hash method inside the create method to hash, salt, and pepper the password and save the resulting value to the password_digest column on the users table.
<code>const hash = bcrypt.hashSync(
        u.password + pepper, 
        parseInt(saltRounds)
      );</code>

## Hashing passwords at user account creation

In this video I'll show how to add bcrypt password hashing when a user is added to the database.
## Video Summary

Here's an example of the bcrypt hashing method with salt and pepper:
```sh
   const hash = bcrypt.hashSync(
      u.password + pepper, 
      parseInt(saltRounds)
   );
```
## Validating passwords at user sign in

In this video I'll show how to add a custom authentication route to our API and how to validate hashed passwords at sign in.
## Video Summary

Here is an example of the bcrypt compare method that checks an incoming password for a match against the hashed password stored in the database
```sh
bcrypt.compareSync(password+pepper, user.password_digest)
```
-------------------------------------------------------
# 4-Quiz: Database Security
## Question 1 of 3
Password hashing is the only technique necessary to protect passwords or other sensitive information in your database to an acceptable level of security.
- true
- (✓) False
## Question 2 of 3
Select any of the following that are true of hashing functions
- (✓) One-way. Passing a string into the function as an argument gets a hash, but passing a hash into the function will not result in the original string.
- Random. Two people running the same hashing function on the same string will not get the same hashed result.
- (✓) Same input gets the same output

- (✓) A small change to the input makes a big change to the output

## Question 3 of 3
A password salt is....
- (✓) 1) a secret string added to the password that makes the hash unusable in a reverse lookup
- 2) a secret password hashed with the password and used to encrypt the hash function
- 3) a secret string added as a fake password through an environment variable to throw off attackers

--------------------------------

## 5-Exercise: Adding a Users Table with Password Hashing
### Implement password hashing with Bcrypt
Your turn! In this exercise you'll need to do the following:
- use migration to create a user table
- Install Bcrypt
- Set up Bcrypt and the Enviroment variables
- Add password hashing to the create route
- Add the authentication route and use Bcrypt to check if the incoming password is correct 
## Excersize readme
## Adding a users table and password hashing
### Getting Started
This exercise contains the book model you created in a previous exercise, your job is to add a users table with a migration, then make sure that passwords are hashed with bcrypt before being stored in the database.
## Environment
### Workspace
This exercise can be done inside of this Udacity workspace. To ready your environment follow these steps:
- In a terminal tab, create and run the database:
   - switch to the postgres user su postgres
   - start psql psql postgres
   - in psql run the following:
      - CREATE USER full_stack_user WITH PASSWORD 'password123';
      - CREATE DATABASE full_stack_dev;
        \c full_stack_dev
      - GRANT ALL PRIVILEGES ON DATABASE full_stack_dev TO full_stack_user;
    to test that it is working run \dt and it should output "No relations found."
### In the 2nd terminal:

Migrations to set up the database table for books from the last section are included in this exercise. To run them, follow the instructions below:
- install yarn npm install yarn -g
- install db-migrate on the machine for terminal commands npm install db-migrate -g
- check node version node -v - it needs to be 10 or 12 level
- IF node was not 10 or 12 level, run
   - npm install -g n
   - n 10.18.0
   - PATH="$PATH"
   - node -v to check that the version is 10 or 12
- install all project dependencies yarn
- to run the migrations db-migrate up
- to test that it is working, run yarn watch should show an app starting on 0.0.0.0:3000
## in the first terminal
```sh
su postgres
psql postgres
// inside sql
CREATE DATABASE full_stack_dev;
\c full_stack_dev
CREATE USER full_stack_user WITH PASSWORD 'password123';
GRANT ALL PRIVILEGES ON DATABASE full_stack_dev TO full_stack_user;
\q
```
## in the second terminal
### teminal
```sh
npm install
npm install yarn -g
yarn add db-migrate -g
yarn add db-migrate-pg -g
yarn add bcrypt
```
### in enviroment file .env
```sh
BCRYPT_PASSWORD=this-is-random
SALT_ROUNDS=10
```
### terminal
```sh
db-migrate create users-table --sql-file
```
### in migration in sql in users up table
```sh
CREATE TABLE users(
id SERIAL PRIMARY KEY,
firstname VARCHAR(100),
lastname VARCHAR(100),
password VARCHAR(200)    
);
```
### in migration in sql in users down table
```sh
DROP TABLE users;
```
### in terminal
```sh
db-migrate up
npm install --save-dev @types/bcrypt
npm i jsonwebtoken
npm i --save-dev @types/jsonwebtoken
```
### create model file user.ts for users
make the following methods to it focus of the create method and adding hasing for password using the no round salt from .env and also bcrypt pepper password
```sh
//@ts-ignore
import Client from "../database";
import bcrypt from "bcrypt";

export type User = {
	id?: number;
	firstname: string;
	lastname: string;
	password: string;
};

const pepper = process.env.BCRYPT_PASSWORD;
const salt_rounds = process.env.SALT_ROUNDS;

export class UserStore {
	async index(): Promise<User[]> {
		try {
			//@ts-ignore
			const conn = await Client.connect();
			const sql = "SELECT * FROM users";
			const result = await conn.query(sql);
			conn.release();
			return result.rows;
		} catch (error) {
			throw new Error(`Could not get users, ${error}`);
		}
	}

	async show(id: number): Promise<User> {
		try {
			//@ts-ignore
			const conn = await Client.connect();
			const sql = "SELECT * FROM users WHERE id=($1)";
			const result = await conn.query(sql, [id]);
			conn.release();
			return result.rows[0];
		} catch (error) {
			throw new Error(`Could not get user ${id}, ${error}`);
		}
	}

	async create(u: User): Promise<User> {
		try {
			//@ts-ignore
			const conn = await Client.connect();
			const sql = "INSERT INTO users (firstname, lastname, password_digest) VALUES($1, $2, $3) RETURNING *";
			const hash = bcrypt.hashSync(u.password + pepper, parseInt(String(salt_rounds)));
			const result = await conn.query(sql, [u.firstname, u.lastname, hash]);
			const user = result.rows[0];
			conn.release();
			return user;
		} catch (err) {
			throw new Error(`unable create user (${(u.firstname, u.lastname)}): ${err}`);
		}
	}

	async update(user: User): Promise<User> {
		try {
			//@ts-ignore
			const conn = await Client.connect();
			const sql = "UPDATE users SET firstname=($2), lastname=($3), password_digest=($4) WHERE id=($1) RETURNING *";
			const hash = bcrypt.hashSync(user.password + pepper, parseInt(String(salt_rounds)));
			const result = await conn.query(sql, [user.id, user.firstname, user.lastname, hash]);
			conn.release();
			return result.rows[0];
		} catch (error) {
			throw new Error(`Could not update user ${user.id}, ${error}`);
		}
	}

	async delete(id: number): Promise<User> {
		try {
			//@ts-ignore
			const conn = await Client.connect();
			const sql = "DELETE FROM users WHERE id=($1) RETURNING *";
			const result = await conn.query(sql, [id]);
			conn.release();
			return result.rows[0];
		} catch (error) {
			throw new Error(`Could not delete user ${id}, ${error}`);
		}
	}

	async authenticate(firstname: string, lastname: string, password: string): Promise<User | null> {
		//@ts-ignore
		const conn = await Client.connect();
		const sql = "SELECT * FROM users WHERE firstname=($1) AND lastname=($2)";
		const result = await conn.query(sql, [firstname, lastname]);
		if (result.rows.length) {
			const user = result.rows[0];
			if (bcrypt.compareSync(password + pepper, user.password_digest)) {
				return user;
			}
		}
		return null;
	}
}
```
### Create user.ts file in the handler folder
add the handler routes to it and also add softtoken to be used in generating the token to be send back to the client  side

```sh
import express, { Request, Response } from "express";
import { User, UserStore } from "../models/user";
import { sign } from "jsonwebtoken";
import Authorize from "../helpers/jwtAuthorizer";

const store = new UserStore();

const index = async (req: Request, res: Response) => {
	try {
		Authorize(req);
	} catch (err) {
		res.status(401);
		return res.json(err);
	}
	const user = await store.index();
	res.json(user);
};

const show = async (req: Request, res: Response) => {
	const id = parseInt(req.params.id);
	if (id === undefined) {
		res.status(400);
		return res.send("Missing or invalid parameters, this endpoint requires the following parameter: id");
	}
	try {
		Authorize(req);
	} catch (err) {
		res.status(401);
		return res.json(err);
	}
	const user = await store.show(id);
	if (user === undefined) {
		res.status(404);
		return res.json("User not found");
	}
	res.json(user);
};

const create = async (req: Request, res: Response) => {
	const { firstname, lastname, password } = req.body;
	if (firstname === undefined || lastname === undefined || password === undefined) {
		res.status(400);
		return res.send("Missing/Invalid parameters, the following parameter are required: firstname, lastname, password");
	}
	const user: User = { firstname, lastname, password };
	try {
		const newUser = await store.create(user);
		var token = sign({ user: { id: newUser.id, firstname, lastname } }, process.env.TOKEN_SECRET as string);
		res.json(token);
	} catch (err) {
		res.status(400);
		res.json(String(err) + user);
	}
};

const update = async (req: Request, res: Response) => {
	const { id, firstname, lastname, password } = req.body;
	if (id === undefined || firstname === undefined || lastname === undefined || password === undefined) {
		res.status(400);
		return res.send(
			"Missing/Invalid parameters, the following parameter are required: id, firstname, lastname, password"
		);
	}
	try {
		Authorize(req, id);
	} catch (err) {
		res.status(401);
		return res.json(err);
	}
	const user: User = { id, firstname, lastname, password };
	try {
		const updated = await store.update(user);
		res.json(updated);
	} catch (err) {
		res.status(400);
		res.json(`${err} ${user}`);
	}
};

const authenticate = async (req: Request, res: Response) => {
	const { firstname, lastname, password } = req.body;
	if (firstname === undefined || lastname === undefined || password === undefined) {
		res.status(400);
		return res.send("Missing/Invalid parameters, the following parameter are required: firstname, lastname, password");
	}
	const user: User = { firstname, lastname, password };
	try {
		const u = await store.authenticate(user.firstname, user.lastname, user.password);
		if (u === null) {
			res.status(401);
			res.json("Incorrect user information");
		} else {
			var token = sign({ user: { id: u.id, firstname, lastname } }, process.env.TOKEN_SECRET as string);
			res.json(token);
		}
	} catch (error) {
		res.status(401);
		res.json({ error });
	}
};

const destroy = async (req: Request, res: Response) => {
	const id = req.body.id;
	if (id === undefined) {
		res.status(400);
		return res.send("Missing/Invalid parameters, the following parameter are required: id");
	}
	try {
		Authorize(req, id);
	} catch (err) {
		res.status(401);
		return res.json("Access denied, invalid token");
	}
	try {
		const deletedUser = await store.delete(id);
		if (deletedUser === undefined) {
			res.status(404);
			return res.json("User doesn't exist");
		} else {
			res.json("ok");
		}
	} catch (err) {
		res.status(400);
		res.json(err);
	}
};

const users_routes = (app: express.Application) => {
	app.get("/users", index);
	app.get("/users/:id", show);
	app.put("/users", update);
	app.post("/users", create);
	app.delete("/users", destroy);
	app.post("/users/login", authenticate);
};

export default users_routes;

```
--------------------------------------------------------------
## 6-Adding a Users Table with Password Hashing Exercise Solution & Review
## Exercise Solution
- Users table
Setting up the migration I ran:
```sh
db-migrate create users-table --sql-file
```
I kept the users table REALLY simple, which is actually all we need for this exercise. The up migration was:
```sh
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100),
    password_digest VARCHAR
);
```
- Installing Bcrypt

Below are the steps copied from the lesson content.
Steps to install Bcrypt
Task List
- Add the dependency: <code>yarn add bcrypt</code>
- Import bcrypt into the user model:
<code>import bcrypt from 'bcrypt'</code>
- Create the necessary environment variables:
<code>BCRYPT_PASSWORD=your-secret-password
SALT_ROUNDS=10</code>
- Use the hash method inside the create method to hash, salt, and pepper the password and save the resulting value to the password_digest column on the users table.
<code>const hash = bcrypt.hashSync(
        u.password + pepper, 
        parseInt(saltRounds)
      );</code>-
- Create and Authenticate methods
Below are copies of the create and authenticate methods
- CREATE
```sh
async create(u: User): Promise<User> {
    try {
      // @ts-ignore
      const conn = await Client.connect()
      const sql = 'INSERT INTO users (username, password_digest) VALUES($1, $2) RETURNING *'
      const hash = bcrypt.hashSync(
        u.password + pepper, 
        parseInt(saltRounds)
      );
      const result = await conn.query(sql, [u.username, hash])
      const user = result.rows[0]
      conn.release()
      return user
    } catch(err) {
      throw new Error(`unable create user (${u.username}): ${err}`)
    } 
  }
```
- AUTHENTICATE
```sh
async authenticate(username: string, password: string): Promise<User | null> {
    const conn = await Client.connect()
    const sql = 'SELECT password_digest FROM users WHERE username=($1)'
    const result = await conn.query(sql, [username])
    console.log(password+pepper)
    if(result.rows.length) {
      const user = result.rows[0]
      console.log(user)
      if (bcrypt.compareSync(password+pepper, user.password_digest)) {
        return user
      }
    }
    return null
  }
```
----------------------------------------------------------

## 7-Introduction to JSON Web Tokens
### JSON Web Tokens (JWTs)
In the next three sections you'll be introduced to JSON web tokens by Udacity instructor Gabriel Ruttner. JWTs are the most common means for authenticating users in decoupled (meaning you have a separate front and back end) web applications. They are secure digital tokens that can be passed between your front end and back end applications to authenticate users and even store important user information. We will be integrating a JWT authentication flow into this API, so get comfy and enjoy the next set of videos by Gabriel!
Quiz Question
### What are some benefits of JWTs?
(Select all that apply.)
- (✓) Stateless
- (✓) Difficult to Fake
- Expensive to Compute
- (✓) Popular and easily implemented across platforms
- (✓) Flexible
--------------------------------------------------------------------

## 8-Storing Data in JWTs
## JWT - Data Structure
Parts of a JSON Web Token
Including Data in Our JWT Payload
the authentic identity of the individual making that request.
## Quiz Question
Which JWT part is responsible for containing information specific to the currently authenticated user?
- Header
- (✓) Payload
- Signature
------------------------------------------------------------
## 9-Validating JWTs
JWT - Validation
## Validating JWT Authenticity
If the signature strings match, we can trust that the data within the JWT is authentic.
```sh
jwt = 
header(algo to make signaturge encoded by base64)
+
payload(not sensitive data including who are sending encoded by base64)
+
signature(algorithm in header function(heaser,payload,SECRET))
```
## Quiz Question
True or False: The signature is used to help encrypt a JWT so it cannot be read without a key
- True
- (✓) False

Additional Resources:
- [JWT.io](https://jwt.io/introduction/) a useful guide and list of popular JSON Web Token implementations.
- [Base64 Encoding](https://en.wikipedia.org/wiki/Base64)
- [HMAC](https://en.wikipedia.org/wiki/HMAC) keyed-hash message authentication code

---------------------------------------------------
## 10-Authentication with JWTs
Now that you have a good sense of what JWTs are and what they can do, we are back with instructor Alyssa Hope to implement JWT authentication in a Node API. First thing we need to do is set up the tools we'll need.
### Add the NPM library jsonwebtoken
- Install the dependancy <code>yarn add jsonwebtoken</code>
- Import the library <code>import jwt from 'jsonwebtoken'</code>
- Create a token<code>jwt.sign()</code>
- Check a token <code>jwt.verify()</code>

## Create JWT at user sign up
In this video I'll go over how to create a token using the jsonwebtoken library and add that step to the user creation flow.
***`it begians with signing  get the password and the username in the client side and hash the password then send it to be saved in the databasew in the backend. after for using token as stateless api microservices instead of session id when trying to sign in with credintials it backend brings the hashed saved key in the database by the username then get the hased  peppered and salted version of the password to be compared with the aaved one if it is okay it capsulate the user information as payload and sign it with its secret key then send this token as replay back and result of sucessesed signing operation so every time we send  asking the backend for something we need to send the token that tells the backend that it is the signed user`***

# The question is can any one take my token and act like me as a user?

## Add JWT validation to an endpoint
In this video I'll show you how to protect private routes by requiring JWT validation.
JWT Authentication Flow - user logs in, this info is sent to the database, a token is generated and sent back to the login for that user.

### JWT Authentication Flow
Video Summary

A quick introduction to how tokens can be required in order to perform certain actions.
Implementing JWTs in a real application

The video above shows in theory how to require a token to be present in order to perform an action. However, there is one big way that the solution above would not be sufficient for a real app, and that is how the JWT is passed to the API. In the video, you may have noticed that I get the token from req.body.token. And this technically works and is easy when testing with Postman and other tools. But in real life, the `token will not be part of the request body`. Instead, tokens live as part of the ***`request header`***.

There are many reasons for this, like added security. But that discussion is a bit outside the scope of this course, what we will focus on instead is how to get the token out of the header and use it in our logic. When we use JWTs, we pass them as a special header called the `Authorization header` using this format:
```sh
Authorization: Bearer <token>
```
Where ***`Bearer`*** is a string separated by the token with a space.

## Getting the header

In Node, we can locate the authorization header sent with a request like this:
```sh
const authorizationHeader = req.headers.authorization
```
Very similar to the way we get the request body.
## Parsing the header
Then, to get the token out of the authorization header, we need to do a little bit of Javascript string parsing. Remember that the word "Bearer" and the token are together as string, separated by a space. We can separate them with this logic:
```sh
const token = authorizationHeader.split(' ')[1]
```
Where we split the string by the space, and take the second item. The second item is the token.
## Putting it all together
Now we have a way to get the token from its correct location in the authorization header, so the code from the video could be revised to look like this:
```sh
const create = async (req: Request, res: Response) => {
    try {
        const authorizationHeader = req.headers.authorization
        const token = authorizationHeader.split(' ')[1]
        jwt.verify(token, process.env.TOKEN_SECRET)
    } catch(err) {
        res.status(401)
        res.json('Access denied, invalid token')
        return
    }

    ....rest of method is unchanged
}
```
And this would work. But to be even more professional about this, let's make this process of requiring token verification easily replicable by turning it into a function.
## Making a custom Express middleware
In the handler file, we are going to add a new function called `verifyAuthToken`. I'll first show you the function, most of the logic is a direct copy from the create method above:
```sh
const verifyAuthToken = (req: Request, res: Response, next) => {
    try {
        const authorizationHeader = req.headers.authorization
        const token = authorizationHeader.split(' ')[1]
        const decoded = jwt.verify(token, process.env.TOKEN_SECRET)

        next()
    } catch (error) {
        res.status(401)
    }
}
```
## Things to note:
This function takes in three arguments, `req` and `res` (exactly like a route handler) and another called `next`. This is how we create a custom Express middleware.

We complete the function, not with a ***return*** but by calling ***next***. If the token could not be verified, we will send that 401 error.

Now, we can tell Express to use this middleware, like this:
```sh
const mount = (app: express.Application) => {
    app.get('/users', index)
    app.get('/users/:id', show)
    app.post('/users', verifyAuthToken, create)
    app.put('/users/:id', verifyAuthToken, update)
    app.delete('/users/:id', verifyAuthToken, destroy)
}
```
So, for the CREATE route, you can see that the request will come in and `verifyAuthToken` will be called before the handler's `create` method.

And that's it! You've created a custom Express middleware!

-----------------------------------------
## 11-Exercise: JWTs in Authentication
Authentication with JWTs Exercise

Do the tasks in the checklist to complete the exercise for this section, then check your work with the solution!
- Add the library jsonwebtoken to the project
- Sign a token as part of the user create action
- Sign a token as part of the user authenticate action 
- Protect the books create route by requiring JWT validation
- Protect the books delete route by requiring JWT validation
- EXTRA GOAL: Use JWTs to protect the user route so that users can only edit their own user settings.
##  Exersice Readme
## Adding JWTs to the authentication flow
### Getting Started
This exercise contains the book model from a previous exercise, as well as the Bcrypt implementation you added earlier.
## Environment Workspace
This exercise can be done inside of this Udacity workspace. To ready your environment follow these steps:
### In a terminal tab, create and run the database:
- switch to the postgres user su postgres
- start psql psql postgres
- in psql run the following:
   - CREATE USER full_stack_user WITH PASSWORD 'password123';
   - CREATE DATABASE
   - full_stack_dev;
   - \c full_stack_dev
   - GRANT ALL PRIVILEGES ON DATABASE full_stack_dev TO full_stack_user;
- to test that it is working run \dt and it should output "No relations found."
### In the 2nd terminal:
Migrations to set up the database tables from the last section are included in this exercise. To run them, follow the instructions below:
- install yarn `npm install yarn -g`
- install db-migrate on the machine for terminal commands `npm install db-migrate -g`
- check node version node -v - it needs to be 10 or 12 level
- IF node was not 10 or 12 level, run
   - npm install -g n
   - n 10.18.0
   - PATH="$PATH"
   - node -v to check that the version is 10 or 12
- install all project dependencies yarn
- to run the migrations db-migrate up
- to test that it is working, run yarn watch should show an app starting on 0.0.0.0:3000
### Local Environment
If want to do this project on your local computer and you already have docker installed, there is a docker file provided for you with generic content. Note that you may need to update this file to fit your computer in order to use it locally.
### Steps to Completion¶
1. Plan to Meet Requirements
2. DB Creation and Migrations
3. Models
4. Express Handlers
5. JWTs
6. QA and Readme
Go to the following pages to get started on the project!

-------------------------------------------

## 12-Authentication with JWTs Exercise Solution & Review
Here are some code examples that fulfill this exercise:
## handlers/users.ts --> CREATE
```sh
const create = async (req: Request, res: Response) => {
    const user: User = {
        username: req.body.username,
        password: req.body.password,
    }
    try {
        const newUser = await store.create(user)
        var token = jwt.sign({ user: newUser }, process.env.TOKEN_SECRET);
        res.json(token)
    } catch(err) {
        res.status(400)
        res.json(err + user)
    }
}
```
## handlers/users.ts --> AUTHENTICATE
```sh
const authenticate = async (req: Request, res: Response) => {
  const user: User = {
    username: req.body.username,
    password: req.body.password,
  }
  try {
      const u = await store.authenticate(user.username, user.password)
      var token = jwt.sign({ user: u }, process.env.TOKEN_SECRET);
      res.json(token)
  } catch(error) {
      res.status(401)
      res.json({ error })
  }
}
```
## handlers/books.ts --> CREATE
```sh
const create = async (req: Request, res: Response) => {
    try {
        const authorizationHeader = req.headers.authorization
        const token = authorizationHeader.split(' ')[1]
        jwt.verify(token, process.env.TOKEN_SECRET)
    } catch(err) {
        res.status(401)
        res.json('Access denied, invalid token')
        return
    }

    try {
        const book: Book = {
            title: req.body.title,
            author: req.body.author,
            total_pages: req.body.total_pages,
            summary: req.body.summary
        }

        const newBook = await store.create(book)
        res.json(newBook)
    } catch(err) {
        res.status(400)
        res.json(err)
    }
}
```
## handler/books.ts --> DELETE
```sh
const destroy = async (req: Request, res: Response) => {
    try {
        const authorizationHeader = req.headers.authorization
        const token = authorizationHeader.split(' ')[1]
        jwt.verify(token, process.env.TOKEN_SECRET)
    } catch(err) {
        res.status(401)
        res.json('Access denied, invalid token')
        return
    }

    try {
        const deleted = await store.delete(req.body.id)
        res.json(deleted)
    } catch (error) {
        res.status(400)
        res.json({ error })
    }
}
```
## Extra Challenge
Make sure users can only edit their own information. The important thing to remember for this is that the token carries the user information - including their id. This is a useful extra challenge because in real world apps, the primary use for JWTs is for authorization, or, figuring out if a person is allowed to do the action they are trying to do. Typically apps will give users roles, and different roles (like ADMIN, or GUEST) have different abilities within the app. Authorization can get pretty tricky so that's as far as I'm going to for now, but its nice to dip a toe into the idea of authorization in this challenge. You'll notice that this example is simplistic, and doesn't do everything that would be required in a real situation, but its just to open up the idea of what can be done with JWTs and authorization.
## handlers/users.ts --> UPDATE
```sh
const update = async (req: Request, res: Response) => {
    const user: User = {
        id: parseInt(req.params.id),
        username: req.body.username,
        password: req.body.password,
    }
    try {
        const authorizationHeader = req.headers.authorization
        const token = authorizationHeader.split(' ')[1]
        const decoded = jwt.verify(token, process.env.TOKEN_SECRET)
        if(decoded.id !== user.id) {
            throw new Error('User id does not match!')
        }
    } catch(err) {
        res.status(401)
        res.json(err)
        return
    }

    try {
        const updated = await store.create(user)
        res.json(updated)
    } catch(err) {
        res.status(400)
        res.json(err + user)
    }
}
```
And if you created a custom middleware for this - great job! You can even create a few different middlewares for different levels of authorization needed - for instance one middleware to look for a valid token and another to check for an admin role on the user, or to check if they are trying to edit a page they don't own.

----------------------------------------------------------
## 13-Exercise: Generating and Verifying JWTs
## Practice - Generating and Verifying JWTs
The following questions will require you to interact with some JWT's. A quick way to do this will be to use the [JWT website](http://jwt.io/) token validator. You can copy and paste the tokens given to you in the questions into the Encoded box, and read the decoded section to find the answers to the questions.

In the question below, you'll find some JWTs. Which of these may have been tampered with? These were signed with the secret `learning`.

```sh
Note: You can triple-click on the tokens given below and then copy and paste them into the notebook.
````
## Question 1 of 2

Which of these JWTs may have been tampered with?
These were signed with the secret learning.
- Token 1
```sh
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXJrIjoiY2VudHJhbCBwYXJrIn0.H7sytXDEHK1fOyOYkII5aFfzEZqGIro0Erw_84jZuGc
```
- Token 2:
```sh
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXJrIjoiYmF0dGVyeSBwYXJrIn0.bQEjsBRGfhKKEFtGhh83sTsMSXgSstFA_P8g2qV5Sns
```
- Token 1
- (✓) Token 2
Now, see if you can decode the JWTs given below.
## Question 2 of 2
```sh
Token A:
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXJrIjoiY2VudHJhbCBwYXJrIn0.H7sytXDEHK1fOyOYkII5aFfzEZqGIro0Erw_84jZuGc
Token B:
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXJrIjoidW5pb24gc3F1YXJlIn0.N3EaAHsrJ9-ls82LT8JoFTNpDK3wcm5a79vYkSn8AFY
Token C:
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXJrIjoiYmF0dGVyeSBwYXJrIn0.bQEjsBRGfhKKEFtGhh83sTsMSXgSstFA_P8g2qV5Sns
```
|JWT|Payload|
|---|---|
|Token A|{'park':'central park'}|
|Token B|{'park':'union square'}|
|Token C|{'park': 'battery park'}|

------------------------------------------------
## 14-Lesson Conclusion
Excellent! In this lesson we've covered some of the data security and authentication strategies for a Node API, here are the topics we covered:
- Password hashing and salt
- Implementing the **bcrypt** library for password hashing
- Introduction to JWT's
- Implementing JWTs with the library **jsonwebtoken**
## Going Further
- For more information on hashing functions, here is a good [resource](https://www.2brightsparks.com/resources/articles/introduction-to-hashing-and-its-uses.html) from 2brightsparks.
- Express [docs](https://expressjs.com/en/guide/writing-middleware.html) on middleware.


