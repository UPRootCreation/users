//
global.count = false;
global.countTwo = false;
//global.timeout = 1000;

global.host = 'host.docker.internal'; //host.docker.internal
//global.host = '172.18.1.4'; //host.docker.internal
global.port = {
  audit: '3000',
};
global.path = {
  audit: '/exec/createRoot',
};
//

var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');
var cors = require('cors');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

//IP
app.set('trust proxy', true);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use('/public', express.static(__dirname + '/public'));
app.use('/services', express.static(__dirname + '/services'));

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({
  secret: 'foo',
  resave: true,
  saveUninitialized: true,
  cookie: {
    expires: 600000
  }
}));
//console.log(new Date(Date.now() + (30 * 86400 * 1000)));

app.use(express.static(path.join(__dirname, 'public')));

// Configurar cabeceras y cors
app.use(cors());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Authorization, X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Allow-Request-Method');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
    res.header('Allow', 'GET, POST, OPTIONS, PUT, DELETE');
    next();
});

app.use('/', indexRouter);
app.use('/users', usersRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  var resp = {message:"error de users - :C | "+err};
  res.send(resp);
  //res.render('error');
});

var mongoose = require('mongoose');
//var mongoDB = 'mongodb://172.18.0.1:27017/users';
var mongoDB = 'mongodb://host.docker.internal:27017/users';
//var mongoDB = 'mongodb://database/users';

var port = process.env.PORT || 3001;

mongoose.connect(mongoDB, {useFindAndModify: false, useUnifiedTopology: true, useNewUrlParser: true}, (err, res) => {
  if(err){
    throw err;
  }else{
    console.log("Conexión exitosa (Base de datos)...");
    app.listen(port, function(){
      console.log("Microservicio 'Users' escuchando en -> http://localhost:"+port);
    });
  }
});
//app.listen(3001);
/*mongoose.connect(mongoDB,{
  useFindAndModify: false,
  useUnifiedTopology: true,
  useNewUrlParser: true});*/
mongoose.Promise = global.Promise;
var db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

module.exports = app;
