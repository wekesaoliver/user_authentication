require("dotenv").config();
const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const {
    DATABASE_URL,
    NODE_ENV,
    PGUSER,
    PGPASSWORD,
    PGHOST,
    PGPORT,
    PGDATABASE,
} = process.env;

const pool = new Pool({
    user: PGUSER,
    password: PGPASSWORD,
    host: PGHOST,
    port: PGPORT,
    database: PGDATABASE,
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

passport.use(
    new LocalStrategy(async (username, password, done) => {
        console.log("LocalStrategy called with", username);
        try {
            const { rows } = await pool.query(
                "SELECT * FROM users WHERE username = $1",
                [username]
            );
            const user = rows[0];

            if (!user) {
                return done(null, false, { message: "Incorrect username" });
            }
            if (user.password !== password) {
                return done(null, false, { message: "Incorrect password" });
            }
            console.log("LocalStrategy success for", username);
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    })
);

passport.serializeUser((user, done) => {
    console.log("serializeUser username:", user.username);
    done(null, user.username);
});

passport.deserializeUser(async (username, done) => {
    try {
        const { rows } = await pool.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );
        const user = rows[0];

        done(null, user);
    } catch (err) {
        done(err);
    }
});

app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    next();
});

app.get("/", (req, res) => {
    console.log("GET / req.user:", req.user);
    res.render("index", { user: req.user });
});
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
    try {
        await pool.query(
            "INSERT INTO users (username, password) VALUES ($1, $2)",
            [req.body.username, req.body.password]
        );
        res.redirect("/");
    } catch (err) {
        return next(err);
    }
});

app.post(
    "/log-in",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/",
    })
);

app.get("/log-out", (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.listen(3000, (error) => {
    if (error) {
        throw error;
    }
    console.log("app listening on port 3000!");
});
