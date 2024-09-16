const model = require("../users/users-model")
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted() {
  return async (req, res, next) => {
		try {
			if (!req.session || !req.session.chocolatechip) {
        // console.log(req.session.user)
					return res.status(401).json({
						message: "You shall not pass!",
					})
			} 
			
			next()
		} catch (err) {
			next(err)
		}
	}
}


/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
function checkUsernameFree() {
return async (req, res, next) => {
  try {
    
    const { username } = req.body
    const user = await model.findBy({ username })
    // console.log(user)
    if (user.length > 0) {
      return res.status(422).json({
        message:"Username taken"
      })
    }
    next()
  } catch(err) {
    next(err)
  }
}
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
function checkUsernameExists() {
  return async (req, res, next) => {
    try {
      const { username } = req.body
    const user = await model.findBy({ username })
    if (user.length < 1) {
      return res.status(401).json({
        message:"Invalid credentials"
      })
    }
    next()
    } catch(err) {
      next(err)
    }
  }
  }


/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength() {
  return (req, res, next) => {
    try {
      // console.log(req.body.password)
      if (!req.body.password || req.body.password <= 3) {
        return res.status(422).json({
          message: "Password must be longer than 3 chars"
        })
      }
        // console.log(req.body.password)
      next()
    
    } catch(err) {
      next(err)
    }
  }
  } 


// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
	restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
}