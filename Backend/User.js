const express = require('express')
const router = express.Router()
const jwt = require('jsonwebtoken')


//mongodb user model
const User = require('./models/User')

//mongodb userVerification model
const UserVerification = require('./models/UserVerification')

//email hander
const nodemailer = require("nodemailer")


//unique string
const{v4: uuidv4} = require("uuid")

//env variable
require("dotenv").config()

//handling password hashing
const bcrypt = require ('bcrypt')

//path for static verified page
const path = require("path")
const { access } = require('fs')

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.AUTH_EMAIL,
        pass: process.env.AUTH_PASS
    }
});


//testing success
transporter.verify((error, success) =>{
    if(error){
        console.log(error)
    } else {
        console.log("Ready for messages")
        console.log(success)
    }
})  

//reset password
router.post('/reset-password', (req, res) => {
    const { email, oldPassword, newPassword, confirmPassword } = req.body;

    if (!email || !oldPassword || !newPassword || !confirmPassword) {
        return res.status(401).json({
            message: "All fields are required"
        });
    }

    if (newPassword === oldPassword) {
        return res.status(401).json({
            message: "The new password cannot be the same as the old password"
        });
    }

    if (newPassword !== confirmPassword) {
        return res.status(401).json({
            message: "New password and confirm password do not match"
        });
    }

    // Verify the old password
    User.findOne({ email })
        .then(user => {
            if (!user) {
                return res.status(401).json({
                    message: "User not found"
                });
            }

            // Check if the old password matches
            bcrypt.compare(oldPassword, user.password, (err, isMatch) => {
                if (err || !isMatch) {
                    return res.status(401).json({
                        message: "Old password is incorrect"
                    });
                }

                // Hash the new password and save it
                bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
                    if (err) {
                        return res.status(500).json({
                            message: "Error hashing new password"
                        });
                    }

                    user.password = hashedPassword;
                    user.save()
                        .then(() => {
                            res.status(200).json({
                                message: "Password has been reset successfully"
                            });
                        })
                        .catch(error => {
                            console.error("Error saving new password:", error);
                            res.status(500).json({
                                message: "An error occurred. Please try again."
                            });
                        });
                });
            });
        })
        .catch(error => {
            console.error("Error finding user:", error);
            res.status(500).json({
                message: "An error occurred. Please try again."
            });
        });
});



//signup
router.post('/signup', (req, res) => {
    let {email, username, role, password} =req.body;
    email = email.trim();
    username = username.trim();
    role = role.trim();
    password = password.trim();

    if(email =="" || username =="" || role =="" || password =="") {
        res.status(401).json({
            message: "Empty input fields!"
        })
    } else if (!/^[\w\s\.\-@]+$/.test(username)) {
        res.status(401).json({
            message: "Invalid username entered!"
        });
    }
     else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
        res.status(401).json({
            message: "Invalid email entered!"
        })
    } else if (role !== "Intern" && role !== "Designer") {
        res.status(401).json({
            message: "Role must be Designer or Intern!"
        });
    }
     else if(password.length < 8) {
        res.status(401).json({
            message: "Password is too short!"
        })
    } else {
        //Checking if user already exists
        User.find({email}).then(result => {
            if (result.length) {
                // A user already exists
                res.status(401).json({
                    message: "User with the provided email already exists"
                });
            } else {
                // Try to create new user
        
                //password handling
                const saltRounds = 10;
                bcrypt.hash(password, saltRounds).then(hashedPassword => {
                    const newUser = new User({
                        email,
                        username,
                        role,
                        password: hashedPassword,
                        verified: false
                    });
        
                    newUser.save().then(result => {
                      //handle email verification
                      sendVerificationEmail(result, res)
                    })
                    .catch(err => {
                        res.status(500).json({
                            message: "An error occurred while saving user account!"
                        });
                    });
                })
                .catch(err => {
                    res.status(500).json({
                        message: "An error occurred while hashing password!"
                    });
                });
            }
        }).catch(err => {
        
            console.long(err);
            res.status(500).json({
                message: "An error occurred while checking for existing user"
            })
        })
    }


})

//send verification email
const sendVerificationEmail =({_id, email}, res) =>{
    //url to be used in the email
    const currentUrl ="http://127.0.0.1:5000/"

    const uniqueString = uuidv4() + _id

    //mail options
    const mailOptions ={
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Verify Your Email",
        html: `<p>Verify your email address to complete the signup and login into your account.</p><p>This link
        <b>expires in 6 hours</b>.</p><p>Press <a href=${currentUrl + "user/verify/" + _id + "/" + uniqueString}>here</a> to proceed.</p>`,

    }

    //hash the unique string
    const saltRounds = 10;
    bcrypt.hash(uniqueString, saltRounds)
        .then((hashedUniqueString) => {
            //set values in userVerification collection
            const newVerification = new UserVerification({
                userId: _id,
                uniqueString: hashedUniqueString,
                createdAt: Date.now(),
                expiresAt: Date.now() + 21600000 //6 hours
            })

            newVerification
            .save()
            .then(() => {
                transporter
                .sendMail(mailOptions)
                .then(() => {
                    //email sent and verification record saved
                    res.status(200).json({
                        message: "Verification email sent"
                    })
                })
                .catch((error) => {
                    console.log(error)
                    res.status(500).json({
                        message: "Verification email failed"
                    })
                })
            })
            .catch((error) =>{
                console.log(error)
                res.status(500).json({
                    message: "Couldn't save verification email data!"
                })
            })


        })
        .catch(() => {
            res.status(500).json({
                message: "An error occured while hasing email data"
            })
        })

}

//verify email
router.get("/verify/:userId/:uniqueString",(req, res) => {
    let{userId, uniqueString} = req.params;

    UserVerification.find({userId})
    .then((result) => {
        if (result.length > 0) {
            //user verification record exists so we proceed

            const {expiresAt} = result[0];
            const hashedUniqueString = result[0].uniqueString;

            // checking for expired unique string
            if (expiresAt < Date.now()) {
                // record has expires so we delete it
                UserVerification
                    .deleteOne({userId})
                    .then(result => {
                        User
                            .deleteOne({_id: userId})
                            .then(() => {
                                let message = "Link expired. Please sign up again"
                                res.redirect(`/user/verified?error=true&message=${message}`)
                            })
                            .catch(error => {
                                let message = "Clearing user with expired unique string failed"
                                res.redirect(`/user/verified?error=true&message=${message}`)
                            })

                        
                    })
                    .catch((error) => {
                        console.log(error);
                        let message = "An error occured while clearing expired user verification record"
                        res.redirect(`/user/verified?error=true&message=${message}`)
                    })
            } else {
                // Valid record exists so we validate the user string
                //First compare the hashed unique string
                
                bcrypt
                    .compare(uniqueString, hashedUniqueString)
                    .then(result => {
                        if (result) {
                            //strings match
                            User.updateOne({_id: userId}, {verified: true})
                            .then(() => {
                                UserVerification
                                    .deleteOne({userId})
                                    .then(() => {
                                        res.sendFile(path.join(__dirname, "../view/verified.html"));
                                    })
                                    .catch(error => {
                                        console.log(error)
                                        let message = "An error occured while finalizing successful verification."
                                        res.redirect(`/user/verified?error=true&message=${message}`)
                                    })
                            })
                            .catch(error => {
                                console.log(error)
                                let message = "An error occured while updating user record to show verified."
                                res.redirect(`/user/verified?error=true&message=${message}`)
                            })
                        } else {
                            //existing record but incorrect verification details passed.
                            let message = "Invalid verification details passed. Check your inbox."
                            res.redirect(`/user/verified?error=true&message=${message}`)
                        }
                    })
                    .catch(error => {
                        let message = "An error occured while comparing unique strings"
                        res.redirect(`/user/verified?error=true&message=${message}`)
                    })
            }
        } else {
            //user verification record doesn't exist
            let message = "Account record doesn't exist or has been verified already. Please sign up or log in."
        res.redirect(`/user/verified?error=true&message=${message}`)
        }
    })
    .catch((error) => {
        console.log(error)
        let message = "An error occured while checking for existing user verification record"
        res.redirect(`/user/verified?error=true&message=${message}`)
    })
})


//verified page route
router.get("/verified", (req, res) =>{
    res.sendFile(path.join(__dirname, "../view/verified.html"))
})

//signin
router.post('/signin', (req, res) => {
    let { username, password } = req.body;
    username = username.trim();
    password = password.trim();

    if (username == "" || password == "") {
        return res.status(401).json({
            message: "Empty credentials supplied!"
        });
    } else {
        // Check if user exists
        User.findOne({ username })
            .then(user => {
                if (!user) {
                    return res.status(401).json({
                        message: "Invalid username!"
                    });
                }

                // Check if user is verified
                if (!user.verified) {
                    return res.status(401).json({
                        message: "User hasn't been verified yet. Check your inbox."
                    });
                }

                // Compare password
                bcrypt.compare(password, user.password)
                    .then(isMatch => {
                        if (!isMatch) {
                            return res.status(401).json({
                                message: "Invalid password entered!"
                            });
                        }

                        // Generate access token
                        const accessToken = jwt.sign(
                            { username: user.username, role: user.role },process.env.ACCESS_TOKEN_SECRET,{ expiresIn: '1h' }
                        );

                        res.status(200).json({
                            message: "Signin successful",
                            data: {
                            email:user.email,
                            username: user.username,
                            password:user.password,
                            verified: user.verified,
                            },
                            role: user.role,
                            accessToken: accessToken
                        });
                    })
                    .catch(err => {
                        res.status(500).json({
                            message: "An error occurred while comparing passwords!"
                        });
                    });
            })
            .catch(err => {
                res.status(500).json({
                    message: "An error occurred while checking for existing user"
                })
            })
    }
})

module.exports = router;