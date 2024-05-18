const express = require('express');
const bcrypt = require('bcrypt');
const { pool } = require('./dbConfig');
const app = express();
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');


const initializePassport = require("./passportConfig");

initializePassport(passport);

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

app.use(
	session({
		secret:"secret",
		resave:false,
		saveUninitialized:false,
	})
);

app.use(passport.initialize());
app.use(passport.session());

app.use(flash())

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/users/register', checkAuthenticated, (req, res) => {
    res.render('register');
});

app.get('/users/login', checkAuthenticated, (req, res) => {
    res.render('login');
});

app.get('/users/logout', (req, res) => {
    req.logOut(err => {
        if (err) {
            console.error(err);
            return res.redirect('/'); // Redirect to homepage or handle error appropriately
        }
        req.flash("success_msg", "You have logged out");
        res.redirect('/users/login');
    });
});

app.get('/users/dashboard', (req, res, next) => {
	if (req.isAuthenticated()) {
        return res.render('dashboard', { user: req.user.name });
    }
    res.redirect('/users/login'); 
});

app.post('/users/register', async (req, res) => {
    let { name, email, password, password2 } = req.body;

    console.log({
        name, email, password, password2
    });

    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ message: 'Please enter all fields' });
        console.log("Errors:", errors);
        return res.render('register', { errors });
    }

    if (password.length < 6) {
        errors.push({ message: "Password should be at least 6 characters" });
        console.log("Errors:", errors);
        return res.render('register', { errors });
    }

    if (password != password2) {
        errors.push({ message: "Password does not match" });
        console.log("Errors:", errors);
        return res.render('register', { errors });
    }

    if (errors.length > 0) {
        res.render('register', { errors });
    } else {
        let hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        pool.query(
            `SELECT * FROM users 
            WHERE email = $1`,
            [email],
            (err, results) => {
                if (err) {
                   throw err;
                }
                console.log("Query results:", results.rows);

                if (results.rows.length > 0) {
                    errors.push({ message: "Email has already been registered" });
                    console.log("Errors:", errors);
                    return res.render('register', { errors });
                }else {
                	pool.query(
                		`INSERT INTO users (name, email, password)
                		VALUES ($1, $2, $3)
                		RETURNING id, password`, [name,email, hashedPassword], (err, results) => {
                			if (err){
                				throw err;
                			}
                			console.log(results.rows);
                			req.flash("success_msg","You are now registered. Login")
                			res.redirect('/users/login');
                		}
                		);
                }
            }
        )
    }
});

app.post("/users/login", passport.authenticate('local',{
	successRedirect:"/users/dashboard",
	failureRedirect:"/users/login",
	failureFlash:true
}));

function checkAuthenticated(req, res, next){
	if (req.isAuthenticated()){
		return res.redirect('/users/dashboard');
	}
	next();
}

function checkNotAuthenticated(req, res, next){
	if (req.isAuthenticated()){
		return next();
	}
	res.redirect('/users/login')
}


const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server is running at port ${port}`));
