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
