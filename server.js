require("./config/db");

const app = require("express")();
const port = 5000;

// app.set('view engine', 'ejs')
// app.use(express.static("public"))

const UserRouter = require("./api/User");
const AdminRouter = require("./api/Admin");

// for accepting post from data
const bodyParser = require("express").json;

var Parser = require('body-parser');
app.use(Parser.json({limit: '20mb'}));

app.use(bodyParser());

const cors = require("cors");
app.use(cors());

app.use("/user", UserRouter);
app.use("/admin", AdminRouter);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

var server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

server.timeout = 120000;
