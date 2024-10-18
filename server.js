const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.get('/',(req, res)=>{
    res.json('hi');

})

app.post('/api/generate', async (req, res) => {
  try {
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${process.env.GEMEINI_API_KEY}`,
      req.body
    );
    res.json(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error generating content');
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
