const express=require("express");
const app = express();
const {pool} = require("./dbConfig");
const bcrypt=require('bcrypt');
const session=require('express-session');
const flash=require('express-flash')
const cookieParser = require("cookie-parser");

const {encryptPriKey,
        getPrivateKey}=require("./src/genPriKey")
const PORT=process.env.PORT||4000;
const passport=require('passport');

const initializePassport=require('./passportConfig')

initializePassport(passport);


app.set('views', '../views');
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({extended:false}));
app.use(cookieParser());

const oneDay = 1000 * 60 * 60 * 24;
app.use(session({
    secret: 'secret',  //encrypt all of our data we store in session
    resave:false, //should we resave our session variable if nothing changes
    cookie:{maxAge: oneDay },
    saveUninitialized:false //do we want to save session details if there has been no changes
}))


app.use(passport.initialize())
app.use(passport.session())

app.use(flash());


app.get('/', (req,res)=>{
    res.render("index");
})

app.get("/users/register", (req,res)=>{
    res.render('register')
})

app.get("/users/dashboard", (req,res)=>{
    res.render('dashboard')
})

app.get("/users/logout", (req,res, next)=>{
    req.logout(function(err) {
        if (err) { return next(err); }
        req.flash('success_msg', 'You have logged out');
        res.redirect('/');
      });
})


// app.post("/users/register", async (req,res)=>{
//     let {email, password, password2}=req.body;
//     // console.log({email, password, password2});

//     let errors=[];

//     if(!email||!password||!password2){
//         errors.push({message: "Please, enter all fields."});
//     }

//     if(password.length<4){
//         errors.push({message: 'Password must be at least 5 characters.'});
//     }

//     if(password!=password2){
//         errors.push({message: "Passwords do not match."});
//     }

//     if(errors.length>0){
//         res.render('register', {errors})
//     }else{
//         let hashedPassword= await bcrypt.hash(password, 3);
//         // console.log(hashedPassword);

//         pool.query(
//             `select * from users
//             where email=$1`, [email], 
//             (err, results)=>{
//                 if(err) {throw err;}
//                 // console.log(results.rows)
//                 if(results.rows.length>0){
//                     errors.push({message: "Email already registered."})
//                     res.render('register', {errors});
//                 }else{
//                     pool.query(
//                         `insert into users (email, password)
//                         values ($1, $2)
//                         returning id, email, password`, [email, hashedPassword],
//                         (err, results)=>{
//                             if(err){
//                                 throw err;
//                             }

//                             console.log(results.rows);
//                             req.flash('success_msg', 'You are now registered. Please, login.')
//                             res.redirect('/');
//                         }
//                     )
//                 }
//             }
           
//         )

//     }

// })


// postgre transaction/ inserting data into 2 tables
app.post("/users/register", async (req,res)=>{
    let {email, password, password2}=req.body;
    // console.log({email, password, password2});

    let errors=[];

    if(!email||!password||!password2){
        errors.push({message: "Please, enter all fields."});
    }

    if(password.length<4){
        errors.push({message: 'Password must be at least 5 characters.'});
    }

    if(password!=password2){
        errors.push({message: "Passwords do not match."});
    }

    if(errors.length>0){
        res.render('register', {errors})
    }else{
        let hashedPassword= await bcrypt.hash(password, 3);
        // console.log(hashedPassword);

        pool.query(
            `select * from users
            where email=$1`, [email], 
            (err, results)=>{
                if(err) {throw err;}
                // console.log(results.rows)
                // success code
                if(results.rows.length>0){
                    errors.push({message: "Email already registered."})
                    res.render('register', {errors});
                }else{
                        const queryText = 'INSERT INTO users (email, password) VALUES($1, $2) RETURNING id, email'
                        pool.query(queryText, [email, hashedPassword], (err, results)=>{
                            if(err){
                                throw err;
                            }
                            // const secondQueryText='insert into addr_data(id, email, password) values ($1, $2, $3)'
                            // const secondQueryVal=[results.rows[0].id, email, hashedPassword]
                            // pool.query(secondQueryText, secondQueryVal, (err, results)=>{
                            //     if(err){
                            //         throw err;
                            //     }
                            //     pool.query('commit', err=>{
                            //         if(err){
                            //             console.error('Error while committing transaction', err.stack)
                            //         }

                                    console.log(results.rows);
                                    req.flash('success_msg', 'You are now registered. Please, login.')
                                    res.redirect('/');
                                
                                 }
                             )  
                     }
                 }
            )    
        }
    } 
)





app.post("/users/login", passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/",
    failureFlash: true
})
)



app.post('/createaddr', async (req,res, done)=>{
 
   const {password}=req.body;
   let user_id = req.session.passport.user;
  

   pool.query(
    `select * from users
    where id=$1`, [user_id], 
    (err, results)=>{
        if(err) {throw err;}

        // success code
        // console.log("results", results.rows)  
        let user;
        
        if(results.rows.length>0){
                user=results.rows[0];
                // console.log("user from createaddr", user);
                bcrypt.compare(password, user.password, (err, isMatch)=> {
                        if(err){
                            throw err;
                        }
    
                        if(isMatch){
                            return done(null, user);
                        }else{
                            return done(null, false, { message: "Password is not correct!"})
                        }
                    })

                // console.log("results after bcrypt", user);

                pool.query(
                    `select * from addr_data where id=$1`,[user.id],
                    (err, results)=>{
                        if(err){
                            throw err;
                        }
                        // success code
                        if(results.rows.length>0){
                            errors.push({message: "You already have TRON address."})
                            res.render('dashboard', {errors});
                        }else{
                            
                            const fnc= encryptPriKey(user.password);
                            // console.log('tronaddress', fnc);
                            const ivHex=fnc.iv.toString('hex');
                            const queryText = 'insert into addr_data (id, email, password, tronaddr, salt, iv, ciphertext) values ($1, $2, $3, $4, $5, $6, $7) RETURNING tronaddr'
                            pool.query(queryText, [user.id, user.email, user.password, fnc.tronAddress, fnc.saltHex,ivHex, fnc.cipherText], (err, results)=>{
                                if(err){
                                    throw err;
                                }
                                    console.log('tron', results.rows[0].tronaddr);
                                    return results.rows[0].tronaddr;
                        })
                
                
                    }
                    
                })
               
        }
        
        // // console.log('new tron address', tronAddrResult)     
        req.flash('success_msg',   `Your new TRON address`)
        res.redirect('/users/dashboard');
    })
})
  



app.listen(PORT, ()=>{
    console.log(`server listening on port ${PORT}`)
})