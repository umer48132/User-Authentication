const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const app = express();
const saltRounds = 10;

app.use(express.json());

const jwtSecret = 'umer'; 
const expiresIn = '1h'; 

const DATABASE_URL = 'mongodb+srv://umerfarooq999000:umerkhan@cluster0.m0d71hr.mongodb.net/nodePortfolio1IEC'; // Replace with your MongoDB connection string

mongoose.connect(DATABASE_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const database = mongoose.connection;

database.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

database.once('connected', () => {
  console.log('Database is connected');
});

const userSchema = new mongoose.Schema({
  name: {
    required: true,
    type: String,
  },
  username: {
    required: true,
    type: String,
    unique: true,
  },
  email: {
    required: true,
    type: String,
    unique: true,
  },
  password: {
    required: true,
    type: String,
  },
});

const User = mongoose.model('User', userSchema);

app.use((err, req, res, next) => {
  console.error(err.stack);

  if (err.name === 'ValidationError') {
    return res.status(400).json({ message: 'Validation failed', errors: err.errors });
  }

  return res.status(500).json({ message: 'Internal server error' });
});

app.post('/register', async (req, res, next) => {
  try {
    const { name, username, email, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ username }, { email }] }).exec();
    if (existingUser) {
      throw new Error('Username or email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, parseInt(saltRounds));

    const newUser = new User({ name, username, email, password: hashedPassword });
    await newUser.save();

    return res.status(201).json({ message: 'User registered successfully', user: newUser });
  } catch (error) {
    return next(error);
  }
});

app.post('/login', async (req, res, next) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username }).exec();

    if (!user) {
      throw new Error('User not found');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      throw new Error('Incorrect password');
    }

    const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn });
    return res.status(200).json({ token });
  } catch (error) {
    return next(error);
  }
});

const invalidatedTokens = [];

app.post('/logout', jwtAuthenticationfunction, (req, res) => {
  const token = req.header('Authorization');

  invalidatedTokens.push(token);

  return res.status(200).json({ message: 'Logged out successfully' });
});

function jwtAuthenticationfunction(req, res, next) {
  let token = req.header('Authorization');
  if (!token) {
    return res.sendStatus(401).json({ message: 'Invalid token' });
  } else {
    jwt.verify(token, jwtSecret, (err, user) => {
      if (err) {
        return res.status(401).json({ message: 'Access denied' });
      } else {
        req.user = user;
        next();
      }
    });
  }
}

app.get('/profile', jwtAuthenticationfunction, (req, res) => {
  return res.status(200).json({ message: 'Profile accessed successfully' });
});

const port = 3001;
app.listen(port, () => {
  console.log('The server is running at port: ' + port);
});
