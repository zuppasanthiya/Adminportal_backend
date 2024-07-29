
import express from 'express';
import { MongoClient } from 'mongodb';
import * as dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import Jwt from 'jsonwebtoken';
import cors from 'cors';

dotenv.config();
const app = express();
const port = process.env.PORT;
const url = process.env.DB;
const client = new MongoClient(url);

app.use(cors());
app.use(express.json());

client.connect().then(() => {
  console.log("Database connected successfully");
  const db = client.db('ZuppaAdminPortal');


  //--------------------------------- Register ------------------------------

  app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const finduser = await db.collection('register').findOne({ email });

    if (finduser) {
      res.status(400).send({ message: 'This user Already exists' });
    } else {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const postSignin = await db.collection('register').insertOne({
        username,
        email,
        password: hashedPassword,
      });
      res.status(200).send({ postSignin, message: 'Register Successfully' });
    }
  });
  //--------------------------------- Login ------------------------------
  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const userFind = await db.collection('register').findOne({ email });

    if (userFind) {
      const passwordCheck = await bcrypt.compare(password, userFind.password);

      if (passwordCheck) {
        const token = Jwt.sign({ id: userFind._id, email: userFind.email }, 'santhiya2525');
        res.status(200).send({ token, user: userFind, message: 'Login Successfully' });
      } else {
        res.status(400).send({ message: 'Invalid Password' });
      }
    } else {
      res.status(400).send({ message: 'Invalid Email id' });
    }
  });
  //---------------------------------  Admin token verify  ------------------------------
  app.post('/verify', async (req, res) => {
    const { token } = req.body;
    try {
      const decoded = Jwt.verify(token, 'santhiya2525');
      const userFind = await db.collection('register').findOne({ _id: new ObjectId(decoded.id) });
      res.status(200).send({ user: userFind });
    } catch (error) {
      res.status(401).send({ message: 'Unauthorized' });
    }
  });


  app.listen(port, () => {
    console.log('Server Running Successfully', port);
  });
});
