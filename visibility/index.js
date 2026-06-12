const express = require('express');

const app = express();

app.get('/', (req,res)=>{
  res.send('SBOM Lab');
});

app.listen(3000, ()=>{
  console.log('Running');
});
