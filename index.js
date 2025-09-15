//IMPORTING THE LIBRARIES
require("dotenv").config();
const express = require("express");
const port = process.env.PORT; // getting port from the .env file
const app = express();
const mysql = require("mysql2");
const bodyParser = require("body-parser"); // Fixed typo: bodyPraser -> bodyParser
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const { error } = require("console");
const JWT_SECRET = process.env.JWT_SECRET;
const fs = require("fs"); //for storing the log in a file
const path = require("path");
const multer = require("multer");
var cors = require("cors");
const { strict } = require("assert");
const crypto = require("crypto");
const axios = require("axios");
const Razorpay = require("razorpay");

const SHIPROCKET_EMAIL = process.env.SHIPROCKET_EMAIL;
const SHIPROCKET_PASSWORD = process.env.SHIPROCKET_PASSWORD;

app.use(express.json());
app.use(cors());

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

//definig the routes in an object
const routes = {
  "/": "view all routes",
  "register as shop keeper": "/api/login",
  "register as shopkeeper": "/api/v1/register/shopkeeper",
  "login as shopkeeper": "/api/v1/login/shopkeeper",
};

//function to get token from shiprocket
async function getAuthToken() {
  try {
    const response = await axios.post(
      "https://apiv2.shiprocket.in/v1/external/auth/login",
      {
        email: "rudtasuhu@gmail.com",
        password: "Om@2002lopa",
      }
    );
    return response.data.token;
  } catch (error) {
    console.error("Auth error:", error.response?.data || error.message);
    throw new Error("Unable to authenticate with Shiprocket");
  }
}

console.log(getAuthToken());

//connecting to the DB

const connection = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  password: "",
  database: "store",
});

connection.connect((err) => {
  if (err) {
    console.error(err.message);
  } else {
    console.log("db connection sucessful");
  }
});

//custom middle wear
function log_request(req, res, next) {
  const hit_path = req.path;
  const method = req.method;
  const time = new Date().toISOString();

  let response = {
    path_requested: hit_path,
    method_requested: method,
    time_requested: time,
  };
  response = JSON.stringify(response, null, 2) + "\n"; // Added newline for better log formatting

  try {
    fs.appendFileSync("./log/log.txt", response);
    console.log(response);
  } catch (err) {
    fs.appendFileSync("./log/err.txt", err.message + "\n");
    console.error("unable to perform the log ");
  }

  next();
}

function auth_handler(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({
      message: "Access to the resource was denied", // Fixed typo: Acess -> Access
    });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        message: "Access to the resource was denied", // Fixed typo: Acess -> Access
      });
    }
    req.user = decoded;
    next();
  });
}

//function to genrate recipt is
function generateRandomAlphaNumeric() {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 5; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    result += chars[randomIndex];
  }
  return result;
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/productMainImage");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname)); // FIXED ✅
  },
});

const filterFile = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const ext = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mime = allowedTypes.test(file.mimetype);

  if (ext && mime) {
    cb(null, true);
  } else {
    cb(new Error("only images allowed"));
  }
};

const upload = multer({
  storage: storage,
  fileFilter: filterFile,
  limits: { fileSize: 2 * 1024 * 1024 }, // FIXED ✅
});

app.use("/", log_request);

//manging routes

app.get("/", (req, res) => {
  res.status(200).json(routes);
});

app.post("/api/v1/register/shopkeeper", async (req, res) => {
  const sql =
    "INSERT INTO shopkeeper (username, storename, password) VALUES (?, ?, ?)";
  const { username, storename, password } = req.body;
  const hashed_password = await bcrypt.hash(password, 10); // Fixed typo: hased_password -> hashed_password

  connection.query(
    sql,
    [username, storename, hashed_password], // Fixed variable name
    (err, result) => {
      if (err) {
        res.status(500).send({
          error: err.message,
        });
      } else {
        res.status(200).send({
          message: "Inserted Successfully", // Fixed typo: Sucessfully -> Successfully
          insertID: result.insertId,
        });
      }
    }
  );
});

app.get("/api/v1/profile/shopkeeper", auth_handler, (req, res) => {
  const sql = "SELECT * FROM shopkeeper WHERE id = ?";
  connection.query(sql, [req.user.id], (err, result) => {
    if (err) {
      return res.status(400).json({
        // Added return statement
        message: "DB ERROR",
      });
    }

    if (result.length === 0) {
      // Added check for empty result
      return res.status(404).json({
        message: "Shopkeeper not found",
      });
    }

    const { username, storename } = result[0];

    res.json({
      data: {
        username: username,
        storename: storename,
      },
    });
  });
});

app.post("/api/v1/login/shopkeeper", async (req, res) => {
  const sql = "SELECT password, id FROM shopkeeper WHERE username = ?";
  const { username, password } = req.body;

  connection.query(sql, [username], async (err, result) => {
    if (err) {
      return res.status(500).send({
        // Added return statement
        error: err.message,
      });
    }

    if (result.length === 0) {
      // Added check for user not found
      return res.status(400).json({
        error: "Invalid Username or password",
      });
    }

    const fetchedPass = result[0].password;
    const isPassCorrect = await bcrypt.compare(password, fetchedPass);
    const userId = result[0].id;

    if (!isPassCorrect) {
      return res.status(400).json({
        // Added return statement
        error: "Invalid Username or password",
      });
    }

    const token = jwt.sign({ username: username, id: userId }, JWT_SECRET, {
      expiresIn: "5h",
    });
    res.json({ token });
  });
});

// Assuming you have 'app', 'auth_handler', 'upload', and 'connection' already defined.

app.post(
  "/api/v1/product/add",
  auth_handler,
  upload.single("image"),
  (req, res) => {
    // 1. Get the authenticated user's ID from the auth_handler middleware
    const shopkeeper_id = req.user.id;

    // 2. Destructure all the required fields from the request body
    const { product_name, description, price, stock, warehouse_id } = req.body;

    // 3. Get the path of the uploaded file from multer
    const image_path = req.file ? req.file.path : null;

    // Basic validation to ensure required fields are present
    if (!product_name || !description || !price || !stock || !warehouse_id) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields. Please fill out the entire form.",
      });
    }

    // 4. Corrected SQL statement with all 7 columns and 7 placeholders
    //    Assuming the 'warehouse_id' from the frontend maps to the 'seller_adresses_id' column in your 'product' table.
    const sql =
      "INSERT INTO product (shopkeeper_id, seller_adresses_id, product_name, description, price, stock, image_path) VALUES (?, ?, ?, ?, ?, ?, ?)";

    // 5. Create an array of values in the correct order to match the SQL statement
    const queryParams = [
      shopkeeper_id,
      warehouse_id, // This value comes from the warehouse dropdown on the frontend
      product_name,
      description,
      price,
      stock,
      image_path,
    ];

    connection.query(sql, queryParams, (err, result) => {
      if (err) {
        console.error("Database Error:", err); // Log the error for debugging
        return res.status(500).json({
          success: false,
          message: "An error occurred while adding the product.",
          error: err.message,
        });
      }

      // Success response
      res.status(201).json({
        success: true,
        message: "Product added successfully!",
        productId: result.insertId,
      });
    });
  }
);

app.get("/api/v1/get/info/product/:id", (req, res) => {
  const productId = req.params.id;

  // 1. MODIFIED SQL QUERY
  // - Corrected the LEFT JOIN to use your exact table name: 'seller_adresses'.
  const sql = `
    SELECT 
        p.product_name, 
        p.description, 
        p.price, 
        p.image_path, 
        p.stock,
        s.storename,
        sa.pincode AS warehouse_pincode 
    FROM 
        product p
    JOIN 
        shopkeeper s ON p.shopkeeper_id = s.id
    LEFT JOIN 
        seller_adresses sa ON p.seller_adresses_id = sa.id -- <-- CORRECTED TABLE NAME HERE
    WHERE 
        p.id = ?
  `;

  connection.query(sql, [productId], (err, result) => {
    if (err) {
      console.error("Database Error on product fetch:", err);
      return res
        .status(500)
        .json({ error: "Failed to retrieve product data." });
    }

    if (result.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    const productData = result[0];

    // 2. RESTRUCTURED JSON RESPONSE (This part remains the same)
    res.status(200).json({
      sold_by: productData.storename,
      product_name: productData.product_name,
      description: productData.description,
      price: productData.price,
      images: [productData.image_path],
      stock: productData.stock,
      warehouse: {
        pincode: productData.warehouse_pincode,
      },
    });
  });
});

app.get("/product/bsid", auth_handler, (req, res) => {
  const sql = "SELECT * FROM product WHERE shopkeeper_id = ?";

  connection.query(sql, [req.user.id], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "No products found" });
    }

    res.json(results);
  });
});

app.get("/product/all", (req, res) => {
  const sql = "SELECT * FROM product";
  connection.query(sql, (err, result) => {
    res.json({ no_of_product: result.length, result });
  });
});

app.post("/api/v1/add/adress/seller", auth_handler, (req, res) => {
  const id = req.user.id;
  const { house_number, area, street, landmark, pincode, city, state } =
    req.body;
  const sql =
    "INSERT INTO seller_adresses (seller_id, house_number, area, street, landmark, pincode, city, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

  connection.query(
    sql,
    [id, house_number, area, street, landmark, pincode, city, state],
    (err, result) => {
      // Fixed parameter name: reult -> result
      if (err) {
        return res.status(400).json({
          error: true,
          errorMessage: err.message,
        });
      }
      res.status(200).json({
        error: false,
        message: "Address Added Successfully", // Fixed typos: messgae -> message, Adress -> Address, Sucessfully -> Successfully
        id: result.insertId, // Fixed parameter name: reult -> result
      });
    }
  );
});

app.get("/api/v1/added/warehouses/", auth_handler, (req, res) => {
  const id = req.user.id;
  const sql1 = "SELECT * FROM seller_adresses WHERE seller_id = ?";
  connection.query(sql1, [id], (err1, results1) => {
    if (err1) {
      console.error("Database error:", err1);
      return res.status(500).json({ error: "Database error" });
    }

    res.json({
      addresses: results1,
    });
  });
});
//============================================ SHOPKEEPER END ENDS HERE ====================================

//============================================ USER END START HERE =====================================

app.post("/api/v1/register/user", async (req, res) => {
  const { name, mobile_number, email_id, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const sql =
    "INSERT INTO users (name, mobile_number, email_id, password) VALUES (?, ?, ?, ?) ";

  connection.query(
    sql,
    [name, mobile_number, email_id, hashedPassword],
    (err, result) => {
      if (err) {
        return res.status(400).json({
          error: true,
          errorMessage: err.message,
        });
      } else {
        res.status(200).json({
          error: false,
          id: result.insertId,
          message: "User inserted successfully", // Fixed typo: USer -> User, sucessfully -> successfully
        });
      }
    }
  );
});

app.post("/api/v1/login/user", async (req, res) => {
  const { email_id, password } = req.body;
  const sql = "SELECT * FROM users WHERE email_id = ?";

  connection.query(sql, [email_id], async (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.length === 0) {
      return res
        .status(400)
        .json({ error: true, message: "Invalid email or password" });
    }

    const isValid = await bcrypt.compare(password, result[0].password); // Fixed: should use async compare
    if (!isValid) {
      return res
        .status(400)
        .json({ error: true, message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: result[0].id, username: result[0].email_id },
      JWT_SECRET,
      {
        expiresIn: "5h",
      }
    );

    res.status(200).json({ token });
  });
});

app.post("/api/v1/add/adress/user", auth_handler, (req, res) => {
  const id = req.user.id;
  const { house_number, area, street, landmark, pincode, city, state } =
    req.body;
  const sql =
    "INSERT INTO user_adresses (user_id, house_number, area, street, landmark, pincode, city, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

  connection.query(
    sql,
    [id, house_number, area, street, landmark, pincode, city, state],
    (err, result) => {
      // Fixed parameter name: reult -> result
      if (err) {
        return res.status(400).json({
          error: true,
          errorMessage: err.message,
        });
      }
      res.status(200).json({
        error: false,
        message: "Address Added Successfully", // Fixed typos: messgae -> message, Adress -> Address, Sucessfully -> Successfully
        id: result.insertId, // Fixed parameter name: reult -> result
      });
    }
  );
});

//making an api for user account page

app.get("/profile/user", auth_handler, (req, res) => {
  const id = req.user.id;

  const sql = "SELECT * FROM users WHERE id = ?";
  connection.query(sql, [id], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const { password, ...userWithoutPassword } = results[0];

    const sql1 = "SELECT * FROM user_adresses WHERE user_id = ?";
    connection.query(sql1, [id], (err1, results1) => {
      if (err1) {
        console.error("Database error:", err1);
        return res.status(500).json({ error: "Database error" });
      }

      res.json({
        user: userWithoutPassword,
        addresses: results1,
      });
    });
  });
});

// Add new address endpoint
app.post("/profile/address", auth_handler, (req, res) => {
  const userId = req.user.id;
  const { house_number, area, street, landmark, pincode, city, state } =
    req.body;

  const sql = `
    INSERT INTO user_adresses (user_id, house_number, area, street, landmark, pincode, city, state) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  connection.query(
    sql,
    [userId, house_number, area, street, landmark || "", pincode, city, state],
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      res.json({
        success: true,
        id: result.insertId,
        message: "Address added successfully",
      });
    }
  );
});

//================================================ PAYMENT SYSTEM USING RAZORPAY =========================

//single item using product id

app.get("/checkout/:id", auth_handler, (req, res) => {
  const productId = req.params.id;
  let sql = "SELECT * FROM product WHERE id = ?";
  connection.query(sql, [productId], async (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.length === 0) return res.json({ error: "no data found" });

    const { shopkeeper_id, product_name, description, price } = result[0];

    try {
      const options = {
        amount: price * 100,
        currency: "INR",
        receipt: generateRandomAlphaNumeric(),
      };
      const order = await razorpay.orders.create(options);

      const insertSql = ` 
        INSERT INTO orders (order_id, product_id, shopkeeper_id, amount, currency, receipt, status) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `; // Fixed typo: inserSql -> insertSql
      connection.query(
        insertSql, // Fixed variable name
        [
          order.id,
          productId,
          shopkeeper_id,
          price,
          options.currency,
          options.receipt,
          "created", // initial status
        ],
        (err2) => {
          if (err2) return res.status(500).json({ error: err2.message });

          res.json({
            key: process.env.RAZORPAY_KEY_ID,
            orderId: order.id,
            amount: order.amount,
            currency: order.currency,
            product: {
              id: productId,
              name: product_name,
              description,
              price,
            },
          });
        }
      );
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
});

app.post("/verify-payment", auth_handler, (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
    req.body;
  try {
    const hmac = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET);
    hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
    const generated_signature = hmac.digest("hex");

    if (generated_signature === razorpay_signature) {
      const sql =
        "UPDATE orders SET status = ?, payment_id = ? WHERE order_id = ?";
      connection.query(
        sql,
        ["paid", razorpay_payment_id, razorpay_order_id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          res.json({ success: true, message: "verified successfully" });
        }
      );
    } else {
      const sql = "UPDATE orders SET status = ? WHERE order_id = ?";
      connection.query(sql, ["failed", razorpay_order_id], (err) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res
          .status(400)
          .json({ success: false, message: "Payment Verification Failed" });
      });
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get("/front-info", (req, res) => {
  const frontInfo = {
    banner_images: ["http://localhost:3000/banner/sky.png"],
    menu_items: [
      { name: "Home", link: "/" },
      { name: "Products", link: "/products" },
      { name: "About Us", link: "/" },
      { name: "Contact", link: "/contact" },
    ],
    footer: {
      text: "© 2025. All in one . All right reserved",
    },
  };
  res.json(frontInfo);
});

function parseShiprocketResponse(apiResponse) {
  // Extract courier companies data
  const courierCompanies = apiResponse.data?.available_courier_companies || [];

  // Map courier data to simplified format
  const couriers = courierCompanies.map((courier) => ({
    courier_patner: courier.courier_name,
    estimated_delivery_days: courier.estimated_delivery_days,
    estimated_delivery_date: courier.etd, // ETD = Estimated Time of Delivery
    rate: courier.rate,
    freight_charge: courier.freight_charge,
  }));

  // Note: The API response doesn't contain pickup_address and delivery_address
  // These would need to be passed from your original request parameters
  return {
    pickup_address: "Not available in API response", // You'll need to get this from your request params
    delivery_address: "Not available in API response", // You'll need to get this from your request params
    couriers: couriers,
  };
}

app.post("/get-recommended-delivery", async (req, res) => {
  const { pickup_postcode, delivery_postcode, weight, cod } = req.body;

  if (!pickup_postcode || !delivery_postcode || !weight || cod === undefined) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const token = await getAuthToken();

    const response = await axios.get(
      "https://apiv2.shiprocket.in/v1/external/courier/serviceability/",
      {
        params: {
          pickup_postcode,
          delivery_postcode,
          weight,
          cod,
        },
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    const apiData = response.data.data;
    const recommendedCourierId = apiData?.recommended_courier_company_id;

    // Find the recommended courier from the available options
    const recommendedCourier = apiData?.available_courier_companies?.find(
      (courier) => courier.courier_company_id === recommendedCourierId
    );

    if (!recommendedCourier) {
      return res.status(404).json({ error: "No recommended courier found" });
    }

    // Return simplified response with just the recommended courier
    const simplifiedResponse = {
      pickup_address: pickup_postcode,
      delivery_address: delivery_postcode,
      courier_name: recommendedCourier.courier_name,
      estimated_delivery_days: recommendedCourier.estimated_delivery_days,
      estimated_delivery_date: recommendedCourier.etd,
    };

    res.json(simplifiedResponse);
  } catch (error) {
    console.error("Shiprocket error:", error.response?.data || error.message);
    res.status(500).json({ error: "Failed to fetch delivery ETA" });
  }
});

app.use("/uploads", express.static(path.join(__dirname, "./")));
app.use(
  "/banner",
  express.static(path.join(__dirname, "uploads/banner_image"))
);

//SERVING THE APP
app.listen(port, (err) => {
  if (err) {
    console.error(`Unable to start the app error is ${err.message}`);
  } else {
    console.log(`E-commerce app serving at http://localhost:${port}`);
  }
});
