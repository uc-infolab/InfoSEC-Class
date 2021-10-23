var fs = require('fs-extra');
var http = require('http');
var https = require('https');
const connectionParameters = require("./app/connection");
const { constants } = require('crypto');
const cookieParser = require('cookie-parser');
const jwt = require("jsonwebtoken");
const jwtsecret = '1234567';


var options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert'),
	//passphrase: "infosec" ,
    //cert: fs.readFileSync('muratozerme.crt'),
    //ca: fs.readFileSync('muratozerme.ca-bundle'),
    secureOptions: constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_TLSv1,
};


var express = require('express');
var app = express();
const expressip = require('express-ip');
var getIpInfoMiddleware = function(req, res, next) {
    var client_ip;
    if (req.headers['cf-connecting-ip'] && req.headers['cf-connecting-ip'].split(', ').length) {
        var first = req.headers['cf-connecting-ip'].split(', ');
        client_ip = first[0];
    } else {
        client_ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress;
    }
    req.client_ip = client_ip;
    next();
};
app.use(expressip().getIpInfoMiddleware);
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});
app.use(cookieParser());

var path = require('path');
var bodyParser = require('body-parser');
//const expressSanitizer = require('express-sanitizer');
var methodOverride = require('method-override');
var server2 = require('http').createServer(app);
var server = https.createServer(options,app);

var passport = require('passport');
require('./config/passport')(passport);
var flash = require('connect-flash');
var validator = require('express-validator');
var exphbs = require('express-handlebars');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
var nodemailer = require('nodemailer');
var hbs = exphbs.create({
    helpers: {
   iff: function (a, b, options) {
    if (a == b) { return options.fn(this); }
    return options.inverse(this); },
    },
	extname: '.hbs', 
	defaultLayout: 'layout', 
	layoutsDir: __dirname + '/public/views/layouts/', 
	partialsDir: __dirname + '/public/views/partials/' 
});
var router = express.Router();
const rateLimit = require("express-rate-limit");
const helmet = require('helmet');
const xss = require('xss-clean');

var session = require('express-session');
var mysql = require('mysql');
var MySQLStore = require('express-mysql-session')(session);
var bcrypt = require('bcrypt');
var redirectToHTTPS = require('express-http-to-https').redirectToHTTPS;

var mysqlPool = mysql.createPool({
    host: connectionParameters[0].host,
    user: connectionParameters[0].user, 
    password: connectionParameters[0].password,
    database: 'infosec',
    connectionLimit: 400
});

module.exports = function (app) {
    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'UCinfosec',
            pass: 'infosec2021!'
        }
    });
    var mailOptions = {
        from: '*****',
        to: '*****',
        subject: 'Sending Email using Node.js',
        text: 'Server was down and restarted. Check the error for further details!'
    };

    //app.use(passport.session()); // persistent login sessions      
        }

var sessionStore = new MySQLStore({   
	clearExpired: true, 
	checkExpirationInterval: 900000, 
	expiration: 86400000,
	endConnectionOnClose: true, 
	charset: 'utf8mb4_bin',
    createDatabaseTable: true,
    schema: {
        tableName: 'users_sessions',
        columnNames: {
			id: 'id',
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    }
}, mysqlPool);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100000 // limit each IP to 100 requests per windowMs
});

// view engine setup
app.engine('.hbs', hbs.engine);
app.set('view engine', '.hbs');
app.set('views', path.join(__dirname, 'public'));
expressValidator = require('express-validator');

var fs = require('fs');

app.use(bodyParser.json({limit: '10mb', extended: true}));
app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
app.use(bodyParser.urlencoded({limit: '10mb', extended: true})); // parse application/x-www-form-urlencoded
app.use(validator());

app.use(session({
    key: 'infoSec',
    secret: '123456',
    store: sessionStore,
    resave: false,
    cookie: { maxAge: 12 * 60 * 60 * 1000 }, //cookie time for 12 hours
    saveUninitialized: true
}));

app.use(helmet());
app.use(function (req, res, next) {
    res.locals.login = req.isAuthenticated();
    //res.locals.session = req.session;
    next();
});

app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use cohasErrorsnnect-flash for flash messages stored in session
//app.use(xss());
app.use(function(req, res, next){
    res.setTimeout(120000, function(element){
        console.error('Request has timed out in the following route -->', element._httpMessage.req.originalUrl);
            res.sendStatus(408);
        });
    next();
});

// Custom flash middleware -- from Ethan Brown's book, 'Web Development with Node & Express'
app.use(function(req, res, next){
    // if there's a flash message in the session request, make it available in the response, then delete it
    res.locals.sessionFlash = req.session.sessionFlash;
    delete req.session.sessionFlash;
    next();
});

// Route that creates a flash message using the express-flash module
app.all('/express-flash', function( req, res ) {
    req.flash('success', 'This is a flash message using the express-flash module.');
    res.redirect(301, '/');
});

const createAccountLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 1 hour window
    max: 500, // start blocking after 5 requests
    message:
        "Too many request created from this IP, please try again later."
});

app.get("/", function (req, res, err) {	
    console.log(req.cookies);
    //res.cookie('infosec','class', {maxAge: 5000})
			res.render('index')
});

app.get('/login', createAccountLimiter, function (req, res, err) {	
        res.render('login', {
            //csrfToken: req.csrfToken(),
            // messages: messages,
            // hasErrors: messages.length > 0,
            token: jwt.sign({name: 'infosec'},jwtsecret),
            title: 'Login'
        });
        
    });

app.get('/users', isLoggedIn, createAccountLimiter, function (req, res, err) {	
        res.render('users', {
            //csrfToken: req.csrfToken(),
            // messages: messages,
            // hasErrors: messages.length > 0,
            title: 'Users'
        });
    });
	
    app.get('/user_edit/(:id)', function (req, res, next) {
        //console.log(req.params.id);
        mysqlPool.getConnection(function (err, db) {
            if (err)
                throw err;
            db.query("Select * from users2 where id=? ",
                [req.params.id], function (err, rows) {
                if (err) {
                    console.log(err);
                }

                //res.json(rows);


                res.render('user_edit', {
                    title: 'User Edit',                   
                    id: rows[0].id,
					first_name: rows[0].first_name,
					last_name: rows[0].last_name,
					username: rows[0].username,
					email: rows[0].email,
                    
                });
                db.release();
            });
        });
    });
	
    app.post('/user_edit', function (req, res, next) {
        //console.log(req.params.id);        
        mysqlPool.getConnection(function (err, db) {
            if (err)
                throw err;
            db.query(`update users2 set username='${req.body.username}', first_name='${req.body.first_name}', last_name='${req.body.last_name}',email='${req.body.email}' where id='${req.body.id}' `,
                [req.params.id], function (err, rows) {
                if (err) {
                    console.log(err);
                }

                //res.json(rows);

                db.release();
            });
        });
    });

app.post('/login', createAccountLimiter, function (req, res, next) {   
    console.log(req.body.token);
    /*
    jwt.verify(req.body.token, jwtsecret, function(err, decoded){
        if(err){
            console.log(err);
            console.log(decoded);
        } else {
            res.json('failure');
            console.log(decoded);
        }
    })
    */ 	
        passport.authenticate('local-login', function (err, user, info) {
            if (err) { return next(err); }
			
            if (!user) {
                var messages = [];
                tokenValidated = false;
                messages.push('Invalid username or password')
                return res.render('login', {
                    //csrfToken: req.csrfToken(),                   
                    messages: messages,
                    hasErrors: messages.length > 0,
                    title: 'Login'
                });
            }

            var map_center=null;
            if(req.ipInfo.ll){
             map_center = req.ipInfo.ll.toString();
            }
            var ip = req.ipInfo.ip;
            var records = [[
                ip, req.ipInfo.country, req.ipInfo.region, req.ipInfo.eu, req.ipInfo.timezone, req.ipInfo.city, map_center, req.ipInfo.metro, req.ipInfo.area, 'Failed Login Page', 'App Server', new Date(), '', '',req.body.username,
            ]]

			
	setTimeout(function(){
		//console.log('machine_name :' + hostname);
		//console.log('hostname: ' + domains);
            mysqlPool.getConnection(function (err, db) {
                if (err) throw err;
                db.query("INSERT INTO remote_logs (ip, country, region, eu, timezone, city, map_center, metro, area, page_name, server_name,created_date, machine_name, hostname, user_name) values ?",
                    [records], function (err, rows) {
                        if (err) {
                            console.log(err);
                        }
                        db.release();
                    });
            });
		},600)

            req.logIn(user, user.role, function (err) {
                //console.log(user);
                if (err) { return next(err); }
                if (user) {
                    return res.redirect('./login2');
				
                }
                // Redirect if it succeeds

                //return res.redirect('/cpd_dashboard');
            });
        })(req, res, next);

    });

    app.get('/login2', isLoggedIn, function (req, res) {
        var ip = req.ipInfo.ip;
        var ip1 = null;
		if(ip){
			ip = ip.replace(/ /g,'')
			ip_parca=ip.split(',')
			ip= ip_parca[0];
			ip1=ip_parca[1];			
		}
        if (ip1==undefined) {ip1='1.1.1.1'}
        if (ip==undefined) {ip1='1.1.1.1'}

        var map_center=null;
        if(req.ipInfo.ll){
         map_center = req.ipInfo.ll.toString();
        }
        //var rangim = req.ipInfo.range.toString();
        var ip = req.ipInfo.ip;
        var records = [[
            ip, req.ipInfo.country, req.ipInfo.region, req.ipInfo.eu, req.ipInfo.timezone, req.ipInfo.city, map_center, req.ipInfo.metro, req.ipInfo.area, 'OTP Page', 'App Server', new Date(), '', '',req.session.passport.user.username,req.session.passport.user.id
        ]]

        
setTimeout(function(){
    //console.log('machine_name :' + hostname);
    //console.log('hostname: ' + domains);
        mysqlPool.getConnection(function (err, db) {
            if (err) throw err;
            db.query("INSERT INTO remote_logs (ip, country, region, eu, timezone, city, map_center, metro, area, page_name, server_name,created_date, machine_name, hostname, user_name, password) values ?",
                [records], function (err, rows) {
                    if (err) {
                        console.log(err);
                    }
                    db.release();
                });
        });
    },600)
console.log(req.session.passport)

        //tokenValidated=false;
        //tokenValidated.push('yeniden');
        console.log(req.session.passport.user.qr_code);
       if (req.session.passport.user.qr_code === null && req.session.passport.user.qr_code_trial <= 10) {			
            return res.redirect('two_factor_register');
        }
        else if (req.session.passport.user.qr_code === null && !(req.session.passport.user.qr_code_trial <= 10)) {
            return res.render("two_factor_register_failed", {
                title: "(2FA) Failed"
            });
        }
        else {
            var token = speakeasy.totp({
                secret: req.session.passport.user.qr_code,
                encoding: 'base32',
            });            
            return res.render('login2', {               
                title: 'Two Factor Authentication'
            });
        }
    });

    app.post('/login2', createAccountLimiter, isLoggedIn, function (req, res) {
        var ip = req.ipInfo.ip;
        var ip1 = null;
		if(ip){
			ip = ip.replace(/ /g,'')
			ip_parca=ip.split(',')
			ip= ip_parca[0];
			ip1=ip_parca[1];			
		}
if (ip1==undefined) {ip1='1.1.1.1'}
if (ip==undefined) {ip1='1.1.1.1'}

        var token = req.body.token; // for testing I am just sending token to front-end. send this token with /verify POST request
        // Verify a given token 
        var tokenValidates = speakeasy.totp.verify({
            secret: req.session.passport.user.qr_code,
            encoding: 'base32',
            token: req.body.token,  //token is what created in get('/') request
            window: 0
        });
		
	
        if (tokenValidates) {
            var map_center=null;
            if(req.ipInfo.ll){
             map_center = req.ipInfo.ll.toString();
            }
            //var rangim = req.ipInfo.range.toString();
            var ip = req.ipInfo.ip;
            var records = [[
                ip, req.ipInfo.country, req.ipInfo.region, req.ipInfo.eu, req.ipInfo.timezone, req.ipInfo.city, map_center, req.ipInfo.metro, req.ipInfo.area, 'Success OTP', 'App Server', new Date(), '', '',req.session.passport.user.username,req.session.passport.user.id
            ]]
            
            
            setTimeout(function(){
            //console.log('machine_name :' + hostname);
            //console.log('hostname: ' + domains);
            mysqlPool.getConnection(function (err, db) {
                if (err) throw err;
                db.query("INSERT INTO remote_logs (ip, country, region, eu, timezone, city, map_center, metro, area, page_name, server_name,created_date, machine_name, hostname, user_name, password) values ?",
                    [records], function (err, rows) {
                        if (err) {
                            console.log(err);
                        }
                        db.release();
                    });
            });
            },600)

            //console.log('I am valid');
            mysqlPool.getConnection(function (err, db) {
                if (err) console.log(err);
                db.query("update users2 set qr_valid=1 where id=?", [req.session.passport.user.id], function (err) {
                    if (err) { console.log(err) }                  
                        res.redirect('/users');
                        
                   
                });
                db.release();
            });
        }
        else {
            if (ip != '::1') {
                var map_center=null;
                if(req.ipInfo.ll){
                 map_center = req.ipInfo.ll.toString();
                }
            //var rangim = req.ipInfo.range.toString();
            var ip = req.ipInfo.ip;
            var records = [[
                ip, req.ipInfo.country, req.ipInfo.region, req.ipInfo.eu, req.ipInfo.timezone, req.ipInfo.city, map_center, req.ipInfo.metro, req.ipInfo.area, 'Failed OTP Page', 'App Server', new Date(), req.session.passport.user.username, req.session.passport.user.id, hostname,ns_name
            ]]
			setTimeout(function(){
            mysqlPool.getConnection(function (err, db) {
                if (err) throw err;
                db.query("INSERT INTO remote_logs (ip, country, region, eu, timezone, city, map_center, metro, area, page_name, server_name,created_date, user_name, password, hostname,ns_name) values ?",
                    [records], function (err, rows) {
                        if (err) {
                            console.log(err);
                        }
                        db.release();
                    });
            });
			},500);
            }
            var messages = [];
            tokenValidated = false;
            messages.push('Please enter a correct/valid token')
            res.render('login2', {
                //csrfToken: req.csrfToken(),
                messages: messages,
                hasErrors: messages.length > 0,
                title: 'Two Factor Authentication'
            });
        }
    });

    app.get('/api/data', function (req, res, next) {
        mysqlPool.getConnection(function (err, db) {
            if (err)
                throw err;
            db.query("SELECT id, first_name, last_name, role, username,email from users2", function (err, subjectDetails2) {
                if (err) {
                    console.log(err);
                }
                res.json(subjectDetails2);
			//	console.log(subjectDetails2)
                db.release();
            });
        });
    });

    app.get('/signup', function (req, res) {
        res.render('signup', {
            title: 'Signup',
            
        });
    }); 
     app.post('/signup', function (req, res) {
                var password = bcrypt.hashSync(req.body.password, 10, null);
            mysqlPool.getConnection(function (err, db) {
                if (err)
                    throw err;
                db.query("SELECT * FROM users2 WHERE username = ? or email = ?", [req.body.username, req.body.email], function (err, rows) {
                    var messages = [];
                    if (err)
                        throw err;
                    if (rows.length) {
                        messages.push(`The '${rows[0].username}' username already registered in infoSEC.`);
                        res.render('signup', {
                            username: req.body.username,
                            password: req.body.password,
                            role: req.body.role,
                            first_name: req.body.first_name,
                            last_name: req.body.last_name,
                            email: req.body.email,
                            messages: messages,
                            hasErrors: messages.length > 0
                        });
                        db.release();
                    } else {  
                        var map_center=null;
                        if(req.ipInfo.ll){
                         map_center = req.ipInfo.ll.toString();
                        }
                        /*
                                    //var rangim = req.ipInfo.range.toString();
                                    var ip = req.ipInfo.ip;
                                    var records = [[
                                        ip, req.ipInfo.country, req.ipInfo.region, req.ipInfo.eu, req.ipInfo.timezone, req.ipInfo.city, map_center, req.ipInfo.metro, req.ipInfo.area, 'Signup', 'App Server', new Date(), req.session.passport.user.username, req.session.passport.user.id
                                    ]]
                                    mysqlPool.getConnection(function (err, db) {
                                        if (err) throw err;
                                        db.query("INSERT INTO remote_logs (ip, country, region, eu, timezone, city, map_center, metro, area, page_name, server_name,created_date,user_name, password) values ?",
                                            [records], function (err, rows) {
                                                if (err) {
                                                    console.log(err);
                                                }
                                                db.release();
                        
                                            });
                                    });
                                    */                      
                        db.query("INSERT INTO users2 (username, password, role, first_name, last_name, email) " +
                            "values (?,?,?,?,?,?)", [req.body.username, bcrypt.hashSync(req.body.password, 10, null), req.body.role, req.body.first_name, req.body.last_name, req.body.email], function (err,result) {
                            if (err) {
                                console.log(err)
                                db.release();
                            } else {                        
                                        db.release();
                                        res.render('index', {
                                            title: 'Sign Up',
                                            secret: 'hey'                                           
                                        });
                                    
                                

 
                            }

                        });

                    }
                });

            });

    });

    app.get('/two_factor_register', isLoggedIn, function (req, res) {
        var secret = speakeasy.generateSecret({ length: 30 });
        var url = speakeasy.otpauthURL({
            secret: secret.base32,
            label: req.session.passport.user.username,
            issuer: 'infoSEC Class',
            encoding: "base32"
        });

        QRCode.toDataURL(url, function (err, data_url, label) {
            res.render('two_factor_register', {
                secret: secret.base32,
                qr_code: data_url,
                label: req.session.passport.user.username,
                qr_code_check: req.session.passport.user.qr_code,
                title: 'Two Factor Registration'
            });
        });
    });

    app.post('/qr_code_register', isLoggedIn, function (req, res) {
		console.log(req.body.kodum)
		console.log(443234423423)
        mysqlPool.getConnection(function (err, db) {
            if (err) throw err;
            db.query("update users2 set qr_code=? Where id=?", [req.body.kodum, req.session.passport.user.id], function (err, subjectDetails2) {
                if (err) {
                    console.log(err);
                }

                res.json(subjectDetails2);
                db.release();
            });
        });
    })

    app.get('/logout', isLoggedIn, function (req, res, next) {
        var ip = req.ipInfo.ip;
        var ip1 = null;
		if(ip){
			ip = ip.replace(/ /g,'')
			ip_parca=ip.split(',')
			ip= ip_parca[0];
			ip1=ip_parca[1];			
		}
        if (ip1==undefined) {ip1='1.1.1.1'};
        if (ip==undefined) {ip1='1.1.1.1'}
        var map_center=null;
        if(req.ipInfo.ll){
         map_center = req.ipInfo.ll.toString();
        }
                    //var rangim = req.ipInfo.range.toString();
                    var ip = req.ipInfo.ip;
                    var records = [[
                        ip, req.ipInfo.country, req.ipInfo.region, req.ipInfo.eu, req.ipInfo.timezone, req.ipInfo.city, map_center, req.ipInfo.metro, req.ipInfo.area, 'Logout', 'App Server', new Date(), req.session.passport.user.username, req.session.passport.user.id
                    ]]
                    mysqlPool.getConnection(function (err, db) {
                        if (err) throw err;
                        db.query("INSERT INTO remote_logs (ip, country, region, eu, timezone, city, map_center, metro, area, page_name, server_name,created_date,user_name, password) values ?",
                            [records], function (err, rows) {
                                if (err) {
                                    console.log(err);
                                }
                                db.release();
        
                            });
                    });

        mysqlPool.getConnection(function (err, db) {
            if (err) throw err;
            db.query("set sql_safe_updates=0");
            db.query("Update sessions set lastseen = ? Where session_id = ?",
                [new Date(), req.session.id]);
            db.query("update sna.users2 set qr_valid=null where id=?", [req.session.passport.user.id], function (err) {
                if (err) { console.log(err) }
            });
            // db.query("Delete from users_sessions Where session_id = ?",  [req.session.id]);
            req.logout();
            req.session.destroy();
            res.redirect('/');
            db.release();
        });
    });
// Route that creates a flash message using custom middleware

    app.get('/logout2', function (req, res, next) {
        console.log('hey');
        mysqlPool.getConnection(function (err, db) {
            if (err) throw err;
            if (session) {
                db.query("set sql_safe_updates=0");
                db.query("Update sessions set lastseen = ? Where session_id = ?",
                    [new Date(), req.session.id]);
                //db.query("Delete from  user_sessions Where session_id = ?",
                //    [req.session.id]);
                if (req.session.passport)
                {
                    db.query("update sna.users2 set qr_valid=null where id=?", [req.session.passport.user.id], function (err) {
                        if (err) { console.log(err) }
                    });
                }
                // db.query("Delete from users_sessions Where session_id = ?",  [req.session.id]);
                req.logout();
                req.session.destroy();
            }
            res.redirect('/login');
            db.release();
        });
    });

    app.get('/siem', function (req, res) {
        res.render('siem', {
            title: 'RMS Records',
            //layout: 'layout_main.hbs',            
            
           
        });
    });

    app.post('/siem_data', isLoggedIn, function (req, res) {
        mysqlPoolMultipleQuery.getConnection(function (err, db) {
            if (err) {
                console.log(err);
                return res.status(500).json({
                    message: 'Connection problem'
                });
            }

            const parameters = [];

            const now = new Date();

            let start_date = moment(now).add(-100, 'years').format('YYYY-MM-DD'); //Min date

            let end_date = moment(now).format('YYYY-MM-DD HH:mm:ss');

            if (req.body.interval == '24hrs')
                start_date = moment(now).add(-1, 'days').format('YYYY-MM-DD HH:mm:ss');
            else if (req.body.interval == '3days')
                start_date = moment(now).add(-3, 'days').format('YYYY-MM-DD HH:mm:ss');
            else if (req.body.interval == '1week')
                start_date = moment(now).add(-7, 'days').format('YYYY-MM-DD HH:mm:ss');
            else if (req.body.interval == '1month')
                start_date = moment(now).add(-1, 'months').format('YYYY-MM-DD HH:mm:ss');
            else if (req.body.interval == '3months')
                start_date = moment(now).add(-3, 'months').format('YYYY-MM-DD HH:mm:ss');
            else if (req.body.interval == '6months')
                start_date = moment(now).add(-6, 'months').format('YYYY-MM-DD HH:mm:ss');
            else if (req.body.interval == '1year')
                start_date = moment(now).add(-1, 'years').format('YYYY-MM-DD HH:mm:ss');
            else if (req.body.interval == 'range') {
                if (req.body.start_date)
                    start_date = req.body.start_date;
                if (req.body.end_date)
                    end_date = req.body.end_date;
            }

            parameters.push(start_date);
            parameters.push(end_date);

            if (req.body.country && req.body.country.length > 0) {
                parameters.push(0);
                parameters.push(req.body.country);
            } else {
                parameters.push(null);
                parameters.push(null);
            }

            if (req.body.page_name && req.body.page_name.length > 0) {
                parameters.push(0);
                parameters.push(req.body.page_name);
            } else {
                parameters.push(null);
                parameters.push(null);
            }

            if (req.body.search) {
                parameters.push(0);
                parameters.push('%' + req.body.search + '%');
                parameters.push('%' + req.body.search + '%');
                parameters.push('%' + req.body.search + '%');
                parameters.push('%' + req.body.search + '%');
                parameters.push('%' + req.body.search + '%');
                parameters.push('%' + req.body.search + '%');
                parameters.push('%' + req.body.search + '%');
                parameters.push('%' + req.body.search + '%');
            } else {
                parameters.push(null);
                parameters.push(null);
                parameters.push(null);
                parameters.push(null);
                parameters.push(null);
                parameters.push(null);
                parameters.push(null);
                parameters.push(null);
                parameters.push(null);
            }

            db.query(`
                DROP TEMPORARY TABLE IF EXISTS user_activity_report;
				DROP TEMPORARY TABLE IF EXISTS watch_list;
                CREATE TEMPORARY TABLE user_activity_report SELECT id, ip, \`range\`, country, region, eu, timezone, city, map_center, metro, area, page_name,user_name, password, server_name, date_format(created_date, '%m/%d/%Y %H') as date_visited, created_date,month(created_date) as month, year(created_date) as year, 1 as value, machine_name, hostname, ns_name, blocked FROM remote_logs WHERE created_date >= ? AND  created_date <= ? AND (? IS NULL OR  country IN (?)) AND ( ? IS NULL OR  page_name IN (?) ) AND (? IS NULL OR  ip LIKE ? OR country LIKE ? OR city LIKE ? OR timezone LIKE ? OR region LIKE ? OR page_name LIKE ? OR user_name LIKE ? OR machine_name LIKE ?); 
				SELECT COUNT(DISTINCT(ip)) as Count,country FROM user_activity_report GROUP BY country; 
				SELECT COUNT(*) as Count,page_name FROM user_activity_report GROUP BY page_name;
				SELECT COUNT(*) as Count,date_visited FROM user_activity_report GROUP BY date_visited;
				SELECT COUNT(*) as Count,Replace(ip,'::ffff:','') as ip, country, city, 1 as value FROM user_activity_report where page_name='success OTP' GROUP BY ip order by COUNT(*) desc;
				SELECT ip, 1 as value, reason FROM blocked_ip where ip is not null GROUP BY ip;
				SELECT count(*) as Count, remote_ip, concat(substring_index(remote_ip,'.',2),'.0.0/16') as cidr,if(blocked_ip.ip is null or blocked_ip.ip='','No', 'Yes') as blocked,1 as value,blocked_ip.reason FROM siem left join blocked_ip on concat(substring_index(remote_ip,'.',2),'.0.0/16') = blocked_ip.ip where http_request like '%robot%' And date_added >= '${start_date}' AND  date_added <= '${end_date}' GROUP BY concat(substring_index(remote_ip,'.',2),'.0.0/16') order by count(*) desc;
				SELECT count(*) as Count, remote_ip, concat(substring_index(remote_ip,'.',2),'.0.0/16') as cidr, http_request,if(blocked_ip.ip is null or blocked_ip.ip='','No', 'Yes') as blocked,1 as value, blocked_ip.reason FROM siem left join blocked_ip on concat(substring_index(remote_ip,'.',2),'.0.0/16') = blocked_ip.ip where http_request like '%robot%' Or (http_request like '%console%' Or http_request like '%owa/auth/logon%' Or http_request like 'index.php/%' Or http_request like '%Autodiscover%' Or http_request like '%solr/%' Or http_request like '%HEAD /%' Or http_request like '%envHTTP%')  And date_added >= '${start_date}' AND  date_added <= '${end_date}' GROUP BY concat(substring_index(remote_ip,'.',2),'.0.0/16') order by count(*) desc;
				create temporary table watch_list select * from (select remote_ip, http_request,date_added FROM siem where http_request not like '%robot%' ANd http_request not like '%HEAD /%' And http_request not like '%.env%'  And date_added >= '${start_date}' AND  date_added <= '${end_date}' group by remote_ip) as a, (select Replace(remote_logs.ip,'::ffff:','') as ip FROM remote_logs where remote_logs.page_name='success OTP' group by ip) as b where a.remote_ip<>b.ip;
				SELECT COUNT(DISTINCT(remote_ip)) as Count,remote_ip,1 as value, concat(substring_index(remote_ip,'.',2)) as search_criter,if(blocked_ip.ip is null or blocked_ip.ip='','No', 'Yes') as blocked, concat(substring_index(remote_ip,'.',2),'.0.0/16') as cidr, blocked_ip.reason FROM watch_list left join blocked_ip on concat(substring_index(remote_ip,'.',2),'.0.0/16') = blocked_ip.ip GROUP BY concat(substring_index(remote_ip,'.',2),'.0.0/16') having COUNT(DISTINCT(remote_ip))>1 order by  COUNT(DISTINCT(remote_ip)) desc;
				Select time, user_percent, systemic, idle, server_name, 1 as value from cpu_alert where created_date>= DATE_ADD(CURDATE(), INTERVAL -1 DAY) And idle<=40;
				`, parameters,
                function (err, results) {
                    if (err) {
                        console.log(err);
                    }
                    res.json({
                        country_data: results[3],
                        page_data: results[4],
                        date_data: results[5],
                        white_data: results[6],
                        black_data: results[7],
                        bot_data: results[8],
                        action_data: results[9],
                        watch_data: results[11],
                        cpu_data: results[12],
                    }); // return all nerds in JSON format
                });

            db.release();
        });
    });  

    app.get('/iprestore/(:ip)', isLoggedIn, function (req, res, next) {
        var ip = req.params.ip.split('_')[0];
        var ip_length = ip.length;
        mysqlPool.getConnection(function (err, db) {
            if (err)
                throw err;
            db.query(`delete from blocked_ip where left(ip,${ip_length})=?`, [ip], function (err) {
                if (err)
                    console.log(err)
            });

            db.query("Select ip from blocked_ip group by ip", function (err, rows) {
                if (err) {
                    console.log(err);
                }

                setTimeout(function () {
                    const textToWrite = rows.map(({
                        ip
                    }) => ip).join('\n');
                    fs.writeFile("public/blocked/blackip.txt", textToWrite, 'utf-8', function (err) {
                        if (err) {
                            console.log(err);
                        }
                        console.log(textToWrite);
                    });
                    console.log(111)

                    res.json('success');
                }, 1500);
                db.release();
            })
        });

    });

    app.post('/ipblock', isLoggedIn,  function (req, res, next) {
        var records = [[req.body.ip + '/32']];
        console.log(req.body.ip);
        mysqlPool.getConnection(function (err, db) {
            if (err)
                throw err;
            db.query("insert into blocked_ip(ip) values ?", [records], function (err) {
                if (err)
                    console.log(err)
            });
            db.query("update remote_logs set blocked=1 where ip=?", [req.body.full_ip], function (err) {
                if (err)
                    console.log(err)
            });
            db.query("Select ip from blocked_ip group by ip", function (err, rows) {
                if (err) {
                    console.log(err);
                }

                setTimeout(function () {
                    const textToWrite = rows.map(({
                        ip
                    }) => ip).join('\n');
                    fs.writeFile("public/blocked/blackip.txt", textToWrite, 'utf-8', function (err) {
                        if (err) {
                            console.log(err);
                        }
                        console.log(textToWrite);
                    });

                    res.send('sucess');
                }, 1500);
                db.release();
            })
        });

    });

    app.post('/ipblock_update', isLoggedIn, function (req, res, next) {
        var ip_length = req.body.cidr.length;

        mysqlPool.getConnection(function (err, db) {
            if (err)
                throw err;
            db.query(`update blocked_ip set reason=? where ip=? or left(ip,${ip_length})=?`, [req.body.reason, req.body.ip, req.body.cidr], function (err) {
                if (err)
                    console.log(err)
            });

            db.release();
        })
        res.send('success');
    });

    const create_server_side_routes = [
        {
               route: 'siem_table_data',
               table_source_database: "",
               table_name: "remote_logs  ",
               historic_check: 'no',
               sql_query1: "SELECT SQL_CALC_FOUND_ROWS id,ip,country,city,timezone,region,page_name,user_name,machine_name, date_format(created_date, '%m/%d/%Y %H:%i:%s') as date_visited FROM ",
               sql_query2: "",
               sql_query3: " created_date >= ? AND created_date <= ? AND (? IS NULL OR country IN (?)) AND (? IS NULL OR page_name IN (?)) ",
               sql_query3_1: " ",
               sql_query4: "",
               search_items: ["ip", "country", "city", "timezone", "region", "page_name", "user_name", "machine_name"],
               sql_order: " Order by id DESC ",
               sql_group: "",
               column_names: ['id',
                   'ip',
                   'country',
                   'city',
                   'timezone',
                   'region',
                   'page_name',
                   'user_name',
                   'machine_name',
                   'date_visited'
               ]
           }, 
           ]
           const moment = require("moment");
           siemAdvancedSearch = function (req) {
               const parameters = [];
             
               const now = new Date();
               let start_date = moment(now).add(-100, "years").format("YYYY-MM-DD");
               let end_date = moment(now).format("YYYY-MM-DD HH:mm:ss");
               if (req.query.interval == "24hrs")
                 start_date = moment(now).add(-1, "days").format("YYYY-MM-DD HH:mm:ss");
               else if (req.query.interval == "3days")
                 start_date = moment(now).add(-3, "days").format("YYYY-MM-DD HH:mm:ss");
               else if (req.query.interval == "1week")
                 start_date = moment(now).add(-7, "days").format("YYYY-MM-DD HH:mm:ss");
               else if (req.query.interval == "1month")
                 start_date = moment(now).add(-1, "months").format("YYYY-MM-DD HH:mm:ss");
               else if (req.query.interval == "3months")
                 start_date = moment(now).add(-3, "months").format("YYYY-MM-DD HH:mm:ss");
               else if (req.query.interval == "6months")
                 start_date = moment(now).add(-6, "months").format("YYYY-MM-DD HH:mm:ss");
               else if (req.query.interval == "1year")
                 start_date = moment(now).add(-1, "years").format("YYYY-MM-DD HH:mm:ss");
               else if (req.query.interval == "range") {
                 if (req.query.start_date) start_date = req.query.start_date;
                 if (req.query.end_date) end_date = req.query.end_date;
               }
             
               parameters.push(start_date);
               parameters.push(end_date);
             
               if (req.query.country) {
                 var countries = req.query.country.split(",");
                 parameters.push(0);
                 parameters.push(countries);
               } else {
                 parameters.push(null);
                 parameters.push(null);
               }
             
               if (req.query.page_name) {
                 var siem_pages = req.query.page_name.split(",");
                 parameters.push(0);
                 parameters.push(siem_pages);
               } else {
                 parameters.push(null);
                 parameters.push(null);
               }
             
               return parameters;
             }; 
       
           function ServerSideRoutes(create_server_side_routes) {
               create_server_side_routes.forEach(route => {
                   //Global Vars
       
                   //End of globals
                   app.get(`/${route.route}`, function (req, res) {
       
                       let join_query = route.sql_query2;
                       let where_conditions = route.sql_query3;
                       var parameters = [];
                       Request = {};
                       var sIndexColumn = '*';
                       sTable = route.table_source_database + route.table_name;
                       column_names = route.column_names;
                       Request = req.query;
                       //Paging
                       sLimit = "limit 10";
                       sLimit = "limit 10";
                       if (Request['iDisplayStart'] && Request['iDisplayLength'] != -1) {
                           sLimit = 'LIMIT ' + Request['iDisplayStart'] + ', ' + Request['iDisplayLength']
                       }
       
                       //console.log(Request['iDisplayStart'] + sLimit);

                       if (route.route == 'siem_table_data') {
                           parameters.push(...siemAdvancedSearch(req));
                       }
       
                       if (route.route == 'user_activity_table_data') {
                           parameters.push(...userActivityAdvancedSearch(req, department_department));
                       }

                       //Ordering
                       var sOrder = "";
                       if (Request['iSortCol_0']) {
                           sOrder = 'ORDER BY ';
       
                           for (var i = 0; i < Request['iSortingCols']; i++) {
                               if (Request['bSortable_' + parseInt(Request['iSortCol_' + i])] == "true") {
                                   sOrder += column_names[parseInt(Request['iSortCol_' + i])] + " " + Request['sSortDir_' + i] + ", ";
                               }
                           }
       
                           sOrder = sOrder.substring(0, sOrder.length - 2)
                           if (sOrder == 'ORDER BY') {
                               // console.log("sOrder == ORDER BY");
                               sOrder = "";
                           }
                       }
       
                       //Filtering
                       var sWhere = "";
                       if (Request['sSearch']) {
                           // if (request['sSearch'].length > 2) {
                           if (Request['sSearch'] && Request['sSearch'] != "") {
                               sWhere = "WHERE (";
                               for (var i = 0; i < route.search_items.length; i++) {
                                   sWhere += route.search_items[i] + ' LIKE ' + '\"%' + Request['sSearch'] + '%\"' + ' OR ';
                               }
       
                               sWhere = sWhere.substring(0, sWhere.length - 4);
                               sWhere += ')';
                           }
                           //console.log(sWhere);
       
       
                       }
       
                       //Individual column filtering
                       for (var i = 0; i < route.search_items.length; i++) {
       
                           if (Request['bSearchable_' + i] && Request['bSearchable_' + i] == "true" && Request['sSearch_' + i] != '') {
                               if (sWhere == "") {
                                   sWhere = "WHERE ";
                               } else {
                                   sWhere += " AND ";
                               }
       
                               const individual_column_search_values = Request['sSearch_' + i].split("|");
       
                               sWhere += " (" + individual_column_search_values.map(search_val => route.search_items[i] + " LIKE '%" + search_val + "%'").join(" OR ") + ") ";
                           }
                       }
       
                       if (sWhere == null || sWhere == "") {
                           sWhere = " Where "
                       } else {
                           sWhere = sWhere + " AND ";
                       }
                       // console.log(sOrder + 11111);
                       sOrder2 = route.sql_order;
                       if (sOrder == "ORDER B" || sOrder == "ORDER BY id asc") {
                           sOrder = sOrder2 + " ";
                       } else {
                           sOrder = sOrder + " ";
                       }
       
                       /*
                       var date_check = sOrder.split('/');
                       if(date_check.length>2){
                       sOrder = date_check[2]+'-'+date_check[0]+'-'+date_check[1];
                       }
                        */
                       //console.log(sOrder);
       
                       var sGroup = route.sql_group;
                       if (route.historic_check == "yes") {
                           if (req.params.id == 0) {
                               where_conditions = ` id>1 `;
                               var sQuery = route.sql_query1 + sTable + join_query + sWhere + where_conditions + (where_conditions && " AND ") + route.sql_query3_1 + sGroup + sOrder + sLimit;
                           }
                           if (req.params.id == 1) {
                               var sQuery = route.sql_query1 + sTable + join_query + sWhere + where_conditions + sGroup + sOrder + sLimit;
                           }
                       } else {
                           var sQuery = route.sql_query1 + sTable + join_query + sWhere + where_conditions + sGroup + sOrder + sLimit;
                       }
       
                       
       
                       var rResult = {};
                       var rResultFilterTotal = {};
                       var aResultFilterTotal = {};
                       var iFilteredTotal = {};
                       var iTotal = {};
                       var rResultTotal = {};
                       var aResultTotal = {};
       
                       //logUserActivity(req.session.passport.user.id, route.route + '_edit')
                       mysqlPool.getConnection(async function (err, db) {
       
                           if (err)
                               throw err;
       
                           
                           await db.query(sQuery, parameters, function selectCb(err, results, fields) {
       
                               if (err) {
                                   console.log(err);
                               }
                               rResult = results;
                               //Data set length after filtering
                               sQuery = "SELECT FOUND_ROWS()";
                               if (err)
                                   throw err;
                               db.query(sQuery, async function selectCb(err, results, fields) {
                                   if (err) {
                                       console.log(err);
                                   }
                                   rResultFilterTotal = results;
                                   aResultFilterTotal = rResultFilterTotal;
                                   iFilteredTotal = aResultFilterTotal[0]['FOUND_ROWS()'];
       
                                   //Total data set length
                                   sQuery = "SELECT COUNT(" + sIndexColumn + ") FROM " + sTable;
       
                                   await db.query(sQuery, parameters, function selectCb(err, results, fields) {
                                       if (err) {
                                           console.log(err);
                                       }
                                       rResultTotal = results;
                                       aResultTotal = rResultTotal;
                                       iTotal = aResultTotal[0]['COUNT(*)'];
       
                                       //Output
                                       var output = {};
                                       var temp = [];
       
                                       output.sEcho = parseInt(Request['sEcho']);
                                       output.iTotalRecords = iTotal;
                                       output.iTotalDisplayRecords = iFilteredTotal;
                                       //output.chartData = ekData;
                                       output.aaData = [];
       
                                       var aRow = rResult;
                                       var row = [];
       
                                       for (var i in aRow) {
                                           for (Field in aRow[i]) {
                                               /*
                                                                           if (route.route == "master_name_list/(:id)") {
                                               var huso =aRow[i].id.toString();
                                               
                                                                               //console.log(encrypt('abc'));
                                                                              
                                                                                   aRow[i].id = encrypt((aRow[i].id).toString());                                                  
                                                                                 
                                                                                       }
                                               */
                                               if (!aRow[i].hasOwnProperty(Field))
                                                   continue;
                                               temp.push(aRow[i][Field]);
                                           }
                                           output.aaData.push(temp);
                                           temp = [];
                                       }
                                       sendJSON(res, 200, output);
       
                                   });
                               });
                           });
                           db.release();
                       });
       
                       async function sendJSON(res, httpCode, body) {
                           var response = JSON.stringify(body);
                           await res.status(200).send(response);
                       }
       
                   });
       
               });
           }
           ServerSideRoutes(create_server_side_routes);
       

app.all('/session-flash', function( req, res ) {
    req.session.sessionFlash = {
        type: 'success',
        message: 'This is a flash message using custom middleware and express-session.'
    }
    res.redirect(301, '/');
});


app.use(methodOverride('X-HTTP-Method-Override')); // override with the X-HTTP-Method-Override header in the request. simulate DELETE/PUT

app.use(express.static(__dirname + '/public')); // set the static files location /public/img will be /img for users



app.use(limiter);

app.use(redirectToHTTPS([/localhost:(\d{4})/], [/\/insecure/], 301));
require('./app/routes')(app); // pass our application into our routes
require("express-stream-json");

server2.listen(80)


server.listen(443,()=>{
console.log('server started')
})


console.log('server started'); 			// shoutout to the user
exports = module.exports = app; 						// expose app
//ALTER USER 'admin'@'localhost' IDENTIFIED WITH mysql_native_password BY 'infoSec2021!?_info'

function isLoggedIn(req, res, next) {               // Express Middleware functions
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
}

function newQR(req, res, next) {
    if (req.session.passport.user.qr_code === null && req.session.passport.user.qr_code_trial <= 10) {
        return next();
    }
    res.redirect('/login2');
}