import JWT from "jsonwebtoken";
import userModel from "../models/userModel.js";

//Protected Routes token base
export const requireSignIn = async (req, res, next) => {
  try {
    const decode = JWT.verify(   // 
      req.headers.authorization,
      process.env.JWT_SECRET
    );
    // Here we are 
    req.user = decode;
    // req.user is like a shared storage for user info that gets passed from one middleware to the next
    next();
    // his moves the request to the next middleware (isAdmin in this case). Since req.user is now attached to the request, the next middleware can use it
  } catch (error) {
    console.log(error);
  }
};

//admin acceess
export const isAdmin = async (req, res, next) => {
  try {
    const user = await userModel.findById(req.user._id);
    if (user.role !== 1) {
      return res.status(401).send({
        success: false,
        message: "UnAuthorized Access",
      });
    } else {
      next();
    }
  } catch (error) {
    console.log(error);
    res.status(401).send({
      success: false,
      error,
      message: "Error in admin middelware",
    });
  }
};




/*                                                Here is what you want to learn about   req.user

When the /test route is requested:

The server receives the request, and it creates a new req object.
Inside the requireSignIn middleware, req.user is created and filled with the user’s decoded information.
The req.user is passed along to the next middleware (isAdmin), and then to the route handler (testController).
As long as the request is being processed (moving through middlewares and route handlers), req.user and all other request-related data exist.
When the request processing ends:

Once the server sends a response back to the client (after the /test route is fully handled), the request is complete.
At this point, the entire req object, including req.user, is destroyed.
This means req.user and all other request-specific data are automatically cleaned up and removed from memory.
If the route is requested again:

If the user makes another request to /test, a new req object will be created, and the requireSignIn middleware will again verify the token and assign req.user. The whole process will repeat.
In summary:
req.user only exists for the duration of the request. It is created when the /test route is requested and destroyed once the server finishes processing the request and sends a response.
Once the route finishes (or you navigate away or stop the route), the entire req object, including req.user, is gone.

*/