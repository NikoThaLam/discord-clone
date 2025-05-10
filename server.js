const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:3001",
    methods: ["GET", "POST"],
    credentials: true
  }
});
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const User = require('./models/User');
const Server = require('./models/Server');

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/chat', { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const userSockets = new Map();

function generateInviteCode() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
}

function authenticate(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) {
    console.log('No token provided for socket connection');
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
    res.cookie('token', token, { httpOnly: true });
    res.json({ token, user: { id: user._id, username: user.username } });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to register' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
    res.cookie('token', token, { httpOnly: true });
    res.json({ token, user: { id: user._id, username: user.username } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/api/servers', authenticate, async (req, res) => {
  try {
    const { name } = req.body;
    const inviteCode = generateInviteCode();
    const server = new Server({
      name,
      owner: req.user.id,
      members: [req.user.id],
      channels: [{ name: 'general' }],
      inviteCode
    });
    await server.save();
    const user = await User.findById(req.user.id);
    user.servers.push(server._id);
    await user.save();
    res.json(server);
  } catch (error) {
    console.error('Server creation error:', error);
    res.status(500).json({ error: 'Failed to create server' });
  }
});

app.get('/api/servers/:serverId/invite', authenticate, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }
    if (!server.members.includes(req.user.id)) {
      return res.status(403).json({ error: 'Not a member of this server' });
    }
    res.json({ inviteCode: server.inviteCode });
  } catch (error) {
    console.error('Error getting invite code:', error);
    res.status(500).json({ error: 'Failed to get invite code' });
  }
});

app.post('/api/servers/join', authenticate, async (req, res) => {
  try {
    const { inviteCode } = req.body;
    const server = await Server.findOne({ inviteCode });
    if (!server) {
      return res.status(404).json({ error: 'Invalid invite code' });
    }
    if (server.members.includes(req.user.id)) {
      return res.status(400).json({ error: 'Already a member of this server' });
    }
    server.members.push(req.user.id);
    await server.save();
    const user = await User.findById(req.user.id);
    user.servers.push(server._id);
    await user.save();
    res.json(server);
  } catch (error) {
    console.error('Error joining server:', error);
    res.status(500).json({ error: 'Failed to join server' });
  }
});

app.post('/api/servers/:serverId/leave', authenticate, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    if (!server) {
      console.log('Server not found:', req.params.serverId);
      return res.status(404).json({ error: 'Server not found' });
    }
    if (!server.members.includes(req.user._id)) {
      console.log('User not a member of server:', { userId: req.user._id, serverId: req.params.serverId });
      return res.status(403).json({ error: 'Not a member of this server' });
    }
    server.members = server.members.filter(member => member.toString() !== req.user._id.toString());
    await server.save();
    req.user.servers = req.user.servers.filter(s => s.toString() !== req.params.serverId);
    await req.user.save();
    const userSocket = userSockets.get(req.user._id.toString());
    if (userSocket) {
      userSocket.leave(req.params.serverId);
    }
    console.log('User left server:', { userId: req.user._id, serverId: req.params.serverId });
    return res.status(200).json({ message: 'Left server successfully' });
  } catch (error) {
    console.error('Error leaving server:', error);
    return res.status(500).json({ error: 'Failed to leave server' });
  }
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

io.on('connection', (socket) => {
  console.log('User connected');
  let userId = null;

  socket.on('authenticate', (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.id;
      userSockets.set(userId, socket);
      console.log('User authenticated:', decoded.username);
    } catch (error) {
      console.error('Socket authentication error:', error);
      socket.disconnect();
    }
  });

  socket.on('joinServer', async (serverId) => {
    if (!userId) return;
    try {
      const server = await Server.findById(serverId);
      if (!server || !server.members.includes(userId)) {
        return;
      }
      socket.join(serverId);
      console.log('User joining server:', { userId, serverId });
      const channel = server.channels.find(c => c.name === 'general');
      if (channel) {
        socket.emit('loadMessages', channel.messages);
        console.log('Loading existing messages:', channel.messages.length);
      }
    } catch (error) {
      console.error('Error joining server:', error);
    }
  });

  socket.on('chatMessage', async (data) => {
    if (!userId) return;
    try {
      const { serverId, message, channel = 'general' } = data;
      const server = await Server.findById(serverId);
      if (!server || !server.members.includes(userId)) {
        return;
      }
      const user = await User.findById(userId);
      const messageData = {
        userId,
        username: user.username,
        message,
        timestamp: new Date()
      };
      const channelObj = server.channels.find(c => c.name === channel);
      if (channelObj) {
        channelObj.messages.push(messageData);
        await server.save();
        io.to(serverId).emit('chatMessage', messageData);
        console.log('Message saved to server');
        console.log('Message broadcasted to server');
      }
    } catch (error) {
      console.error('Error handling chat message:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected');
    if (userId) {
      userSockets.delete(userId);
    }
  });
});

const PORT = process.env.PORT || 3001;
http.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 