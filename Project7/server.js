/*****************************************************
 * Name: Zack Chand
 * Date: 11/17/2023
 * Assingment # 7 
 * 
 */
const axios = require('axios');
const { auth } = require('express-openid-connect');
const { requiresAuth } = require('express-openid-connect');
const express = require('express');
const { Datastore } = require('@google-cloud/datastore');
const datastore = new Datastore();
const jwt = require('jsonwebtoken');
const port = process.env.PORT || 8080;
const app = express();
app.use(express.json()); 

// Middleware to parse JSON

// Middleware to validate JWT

//https://auth0.com/docs/quickstart/webapp/express
const config = {
    authRequired: false,
    auth0Logout: true,
    secret: '72b54d5bf5b00145f3dbdacfee066232040a960c90e6f5d8a9d97dbf04d9075c', 
    baseURL: 'http://localhost:8080', 
    clientID: '1epRqGwYTb0omSyHOGbB0g6U9H87OZvV',
    issuerBaseURL: 'https://dev-cyp3zjp5x2yflr0h.us.auth0.com',
  };

  // middleware to use config auth router attaches /login, /logout, and /callback routes to the baseURL
  app.use(auth(config));
  // Middleware to validate JWT
  function validateJwt(req, res, next) {
        //Grab the token
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
          req.isJwtValid = false;
          return next();
      }
      jwt.verify(token, '72b54d5bf5b00145f3dbdacfee066232040a960c90e6f5d8a9d97dbf04d9075c', (err, decoded) => {
          if (err) {
              req.isJwtValid = false;
          } else {
              req.isJwtValid = true;
              req.jwtPayload = decoded;
          }
          next();
      });
  }
app.get('/', async (req, res) => {
    if (req.oidc.isAuthenticated()) {
        try {
            const tokenResponse = await axios.post(`https://dev-cyp3zjp5x2yflr0h.us.auth0.com/oauth/token`, {
                username: 'wallace@cheese.com',
                password: 'Cheese@2023',
                client_id: '1epRqGwYTb0omSyHOGbB0g6U9H87OZvV',
                client_secret: 'BMQ36NFeUE-XDzTXVU9hu3RlETckZR-TGJoM4A438UbgG5uBKdDtPW7S6_-PFgVU',
                grant_type: "password"
            });

            console.log('Access Token:', tokenResponse.data.access_token);
            res.send('Logged in. Token: ' + tokenResponse.data.access_token);
        } catch (error) {
            console.error('Error getting Auth0 token:', error);
            res.status(500).send('Error getting Auth0 token');
        }
    } else {
        res.send('Logged out');
    }
});


  // Secure the endpoint 
  app.get('/protected', (req, res) => {
    if (!req.oidc.isAuthenticated()) {
      res.status(401).send('Not logged in');
    } else {
      // Protected content
    }
  });
  app.get('/profile', requiresAuth(), (req, res) => {
    res.send(JSON.stringify(req.oidc.user));
  });
    
// Create a new boat
app.post('/boats', validateJwt, async (req, res) => {
    // Check if JWT is valid
    if (!req.isJwtValid) {
        return res.status(401).send({ Error: "Unauthorized" });
    }

    try {
        // Extract boat data from the request body
        const { name, type, length, public } = req.body;

        // Validate the boat data
        if (!name || !type || !length || typeof public === 'undefined') {
            return res.status(400).json({ Error: "The request object is missing at least one of the required attributes" });
        }

        // Set owner to the sub property from JWT
        const owner = req.jwtPayload.sub;

        // Create a new key for the boat
        const kind = 'Boat';
        const boatKey = datastore.key(kind);

        // Create a new boat entity
        const newBoat = {
            key: boatKey,
            data: {
                name,
                type,
                length,
                public,
                owner
            } 
        };

        await datastore.save(newBoat);

        // Update the self URL after saving the boat
        var self = `${req.protocol}://${req.get('host')}${req.originalUrl}/${boatKey.id}`;
        newBoat.data.self = self;

        await datastore.save(newBoat);

        // Return a response with the boat entity and its ID
        return res.status(201).json({
            id: newBoat.key.id,
            name: newBoat.data.name,
            type: newBoat.data.type,
            length: newBoat.data.length,
            public: newBoat.data.public,
            owner: newBoat.data.owner,
            self: newBoat.data.self
        });
    } catch (error) {
        console.error('Error adding boat:', error);
        return res.status(500).json({ Error: "An internal server error occurred." });
    }
});


// Get all the boats from a single owner
app.get('/owners/:owner_id/boats', async (req, res) => {
    const owner_id = req.params.owner_id;

    try {
        const query = datastore.createQuery('Boat')
                               .filter('owner', '=', owner_id)
                               .filter('public', '=', true);

        const [boats] = await datastore.runQuery(query);
        
        // Format boats to include necessary properties
        const formattedBoats = boats.map(boat => ({
            id: boat[datastore.KEY].id,
            name: boat.name,
            type: boat.type,
            length: boat.length,
            public: boat.public,
            owner: boat.owner,
            self: `${req.protocol}://${req.get('host')}/boats/${boat[datastore.KEY].id}`
        }));

        res.status(200).json(formattedBoats);
    } catch (error) {
        console.error('Error fetching boats:', error);
        res.status(500).json({ Error: "An internal server error occurred." });
    }
});
app.get('/boats', validateJwt, async (req, res) => {
    try {
        let query;
        if (req.isJwtValid) {
            // Fetch boats based on owner in JWT
            const ownerSub = req.jwtPayload.sub; // Assuming 'sub' is in the JWT payload
            query = datastore.createQuery('Boat').filter('owner', '=', ownerSub);
        } else {
            // Fetch all public boats
            query = datastore.createQuery('Boat').filter('public', '=', true);
        }

        const [boats] = await datastore.runQuery(query);
        
        // Format boats to include necessary properties
        const formattedBoats = boats.map(boat => ({
            id: boat[datastore.KEY].id,
            name: boat.name,
            type: boat.type,
            length: boat.length,
            public: boat.public,
            owner: boat.owner,
            self: `${req.protocol}://${req.get('host')}/boats/${boat[datastore.KEY].id}`
        }));

        res.status(200).json(formattedBoats);
    } catch (error) {
        console.error('Error fetching boats:', error);
        res.status(500).json({ Error: "An internal server error occurred." });
    }
});
app.delete('/boats/:boat_id', validateJwt, async (req, res) => {
    if (!req.isJwtValid) {
        return res.status(401).send({ Error: "Unauthorized" });
    }

    const boat_id = req.params.boat_id;
    const key = datastore.key(['Boat', datastore.int(boat_id)]);

    // Fetch the boat entity
    const [boat] = await datastore.get(key);

    // Check if boat exists and if the JWT's sub matches the boat's owner
    if (!boat) {
        return res.status(403).send({ Error: "No boat with this boat_id exists" });
    } else if (boat.owner !== req.jwtPayload.sub) {
        return res.status(403).send({ Error: "Forbidden" });
    }

    await datastore.delete(key);
    res.status(204).send();
});


app.listen(port, () => {
    console.log(`API is running on port ${port}`);
});