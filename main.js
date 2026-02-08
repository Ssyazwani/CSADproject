const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();

// Body parser
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session setup
app.use(session({
  secret: "your-secret-key", 
  resave: false,
  saveUninitialized: false
}));

// MySQL connection
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "", // .env
  database: "booking_system"
});

connection.connect(err => {
  if (err) {
    console.error("MySQL connection failed:", err.message);
    process.exit(1);
  }
  console.log("MySQL connected");
});

app.use(express.static("public"));




app.post("/CreateAccount", async (req, res) => {
  const { email, password, name, block, floor, unit } = req.body;

  // Check if email exists
  const sqlCheck = "SELECT * FROM users WHERE email = ?";
  connection.query(sqlCheck, [email], async (err, rows) => {
    if (err) return res.status(500).send("Database error");

    if (rows.length > 0) return res.send("<p>Email already exists</p>");

 
    try {
      const hashedPassword = await bcrypt.hash(password, 10); // saltRounds = 10

      const sqlInsert = `
        INSERT INTO users (email, password, name, block, floor, unit)
        VALUES (?, ?, ?, ?, ?, ?)
      `;
      connection.query(sqlInsert, [email, hashedPassword, name, block, floor, unit], (err, result) => {
        if (err) return res.status(500).send("Insert failed");
        res.send(`<p>Account created for ${name}. <a href="/LoginPage.html">Login here</a></p>`);
      });

    } catch (hashErr) {
      console.error(hashErr);
      res.status(500).send("Error hashing password");
    }
  });
});


app.post("/LoginAccount", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT id, password, role FROM users WHERE email = ?";
  connection.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).send("Database error");

    if (results.length === 0) {
      return res.send("<p>Invalid email or password</p>");
    }

    const user = results[0];

    // Compare the hashed password
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send("<p>Invalid email or password</p>");

    // Successful login
    req.session.userId = user.id;
    req.session.role = user.role;

    if (user.role === "admin") {
      res.redirect("/admin.html");
    } else {
      res.redirect("/Dashboard.html");
    }
  });
});


app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/LoginPage.html");
  });
});

// Protect booking page
app.get("/book.html", (req, res, next) => {
  if (!req.session.userId) return res.redirect("/LoginPage.html");
  next(); // allow access
});

// Protect user bookings page
app.get("/userbookings.html", (req, res, next) => {
  if (!req.session.userId) return res.redirect("/LoginPage.html");
  next();
});

app.get("/dashboard.html", (req, res, next) => {
  if (!req.session.userId) return res.redirect("/LoginPage.html");
  next();
});



// Create booking
app.post("/createBooking", (req, res) => {
  if (!req.session.userId) return res.redirect("/LoginPage.html");

  const { selectedFacility, selectedDate, selectedCourt, selectedTime } = req.body;

  const sql = `
    INSERT INTO bookings (user_id, facility, date, court, timeSlot)
    VALUES (?, ?, ?, ?, ?)
  `;
  connection.query(sql, [req.session.userId, selectedFacility, selectedDate, selectedCourt, selectedTime], err => {
    if (err) return res.status(500).send("Error saving booking");
    res.send("<p>Booking successful! <a href='/book.html'>Book another</a></p>");
  });
});

// Get booked slots for facility/date
app.get("/getBookings", (req, res) => {
  const { facility, date } = req.query;
  const sql = "SELECT court, timeSlot FROM bookings WHERE facility = ? AND date = ?";
  connection.query(sql, [facility, date], (err, results) => {
    if (err) return res.status(500).send(err);
    const booked = results.map(r => `${r.court}-${r.timeSlot}`);
    res.json(booked);
  });
});

// Get logged-in user's bookings
app.get("/api/user-bookings", (req, res) => {
  if (!req.session.userId) return res.status(401).end();

  const sql = `
    SELECT facility, date, court, timeSlot
    FROM bookings
    WHERE user_id = ?
    ORDER BY date, timeSlot
  `;

  connection.query(sql, [req.session.userId], (err, results) => {
    if (err) return res.status(500).send("Database error");
    res.json(results);
  });
});

// Cancel a booking
app.post("/api/cancel-booking", (req, res) => {
  if (!req.session.userId) return res.status(401).send("Not logged in");

  const { bookingId } = req.body;

  // Only allow deletion if the booking belongs to the logged-in user
  const sql = "DELETE FROM bookings WHERE id = ? AND user_id = ?";
  connection.query(sql, [bookingId, req.session.userId], (err, result) => {
    if (err) return res.status(500).send("Database error");

    if (result.affectedRows === 0) {
      return res.status(403).send("Booking not found or cannot cancel");
    }

    res.send({ success: true, message: "Booking cancelled successfully" });
  });
});

// Admin
function isAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect("/LoginPage.html");

  const sql = "SELECT role FROM users WHERE id = ?";
  connection.query(sql, [req.session.userId], (err, results) => {
    if (err) return res.status(500).send("Database error");
    if (results.length === 0 || results[0].role !== "admin") {
      return res.status(403).send("Access denied");
    }
    next();
  });
}


// Fetch bookings for a date range
app.get("/api/admin-bookings", isAdmin, (req, res) => {
  let { startDate, endDate } = req.query;

  let sql = `
    SELECT b.id, b.user_id, b.facility, b.date, b.court, b.timeSlot, u.email
    FROM bookings b
    JOIN users u ON b.user_id = u.id
  `;
  const params = [];

  if (startDate && endDate) {
    sql += ` WHERE b.date BETWEEN ? AND ?`;
    params.push(startDate, endDate);
  }

  sql += ` ORDER BY b.date, b.timeSlot`;

  connection.query(sql, params, (err, results) => {
    if (err) return res.status(500).send("Database error");
    res.json(results);
  });
});

// Create a new booking for admin
app.post("/api/admin-create-booking", isAdmin, (req, res) => {
  const { userId, facility, date, court, timeSlot } = req.body;

  const sql = `
    INSERT INTO bookings (user_id, facility, date, court, timeSlot)
    VALUES (?, ?, ?, ?, ?)
  `;

  connection.query(sql, [userId, facility, date, court, timeSlot], (err) => {
    if (err) return res.status(500).send("Database error");
    res.send({ success: true, message: "Booking created successfully" });
  });
});

// Update an existing booking for admin
app.post("/api/admin-update-booking", isAdmin, (req, res) => {
  const { bookingId, facility, date, court, timeSlot } = req.body;

  const sql = `
    UPDATE bookings
    SET facility = ?, date = ?, court = ?, timeSlot = ?
    WHERE id = ?
  `;

  connection.query(sql, [facility, date, court, timeSlot, bookingId], (err) => {
    if (err) return res.status(500).send("Database error");
    res.send({ success: true, message: "Booking updated successfully" });
  });
});

// Delete a booking for admin
app.post("/api/admin-delete-booking", isAdmin, (req, res) => {
  const { bookingId } = req.body;
  const sql = "DELETE FROM bookings WHERE id = ?";
  connection.query(sql, [bookingId], (err) => {
    if (err) return res.status(500).send("Database error");
    res.send({ success: true, message: "Booking deleted successfully" });
  });
});

// Fetch all users (for admin create booking dropdown)
app.get("/api/users", isAdmin, (req, res) => {
  connection.query("SELECT id, email FROM users", (err, results) => {
    if (err) return res.status(500).send("Database error");
    res.json(results);
  });
});



const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));