const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const twilio = require('twilio');
const useragent = require('express-useragent');
const fs = require('fs');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Initialize log storage
const userActionLogs = [];

/* PostgreSQL setup
const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});
*/

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
// Twilio setup
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const messagingServiceSid = process.env.TWILIO_MESSAGING_SERVICE_SID;

const templates = {
  welcome: 'HX7b9af88ec44919c719c326d72d222b06',
  appointmentCreated: 'HX7857fc65ec30c769d83b695043f036bd',
  bookingConfirmed: 'HXe1bdbaa93d62c2f1485e9a4430e81a8a',
  shiftingCompleted: 'HXb4e3fba74aa16c82ac44be04239fa35d'
};

const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;
const whatsappPhoneNumber = process.env.WHATSAPP_PHONE_NUMBER;
const ownerNumber = process.env.OWNER_NUMBER;
const salesNumbers = {
  Vijayawada: process.env.SALES_NUMBER_VIJAYAWADA,
  Vizag: process.env.SALES_NUMBER_VIZAG
};

// Middleware
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

app.use(useragent.express());

function isAuthenticated(req, res, next) {
  if (req.session.user) {
    console.log('User is authenticated:', req.session.user); // Debug log
    return next();
  } else {
    console.log('User not authenticated, redirecting to login page'); // Debug log
    res.redirect('/');
  }
}
/*
function checkRole(role) {
  return function (req, res, next) {
    if (req.session.user && req.session.user.role === role) {
      console.log('User role is authorized:', req.session.user.role); // Debug log
      next();
    } else {
      console.log('Forbidden: User role is not authorized or not logged in'); // Debug log
      res.status(403).send('Forbidden: User role is not authorized or not logged in');
    }
  };
}
  */


// MIDDLE WARE LOGIC FOR  CHECK ROLES 
function checkRole(...roles) {
  return function (req, res, next) {
    if (req.session.user && roles.includes(req.session.user.role)) {
      next();
    } else {
      // Redirect to the staff page if the user role is staff
      if (req.session.user.role === 'staff') {
        res.redirect('/staff');
      } else {
        res.status(403).send('Forbidden');
      }
    }
  };
}

module.exports = { isAuthenticated, checkRole };



// Log Middleware
app.use((req, res, next) => {
  const actionLog = {
    action: `${req.method} ${req.url}`,
    dateTime: new Date().toISOString()
  };
  userActionLogs.push(actionLog);
  fs.writeFileSync('userActionLogs.json', JSON.stringify(userActionLogs, null, 2));
  next();
});

// Set view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Serve login.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Serve index.html
app.get('/index', isAuthenticated,checkRole('admin','user'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Serve otp.html
app.get('/otp', (req, res) => {
  const email = req.session.email;
  res.render('otp', { email });
});

// Serve backup-code.html
app.get('/backup-code', (req, res) => {
  const email = req.session.email;
  res.render('backup-code', { email, error: null });
});

// Serve other HTML files
app.get('/new-appointment',isAuthenticated, checkRole('admin','user'),(req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'new-appointment.html'));
});

app.get('/filter-appointments', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'filter-appointments.html'));
});

app.get('/settings', isAuthenticated, checkRole('admin','user'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'settings.html'));
});

app.get('/send', isAuthenticated,checkRole('admin','user'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'send.html'));
});

app.get('/todays-bookings', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'todays-bookings.html'));
});

app.get('/total-bookings', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'total-bookings.html'));
});

app.get('/not-booked', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'not-booked.html'));
});

app.get('/todays-shiftings', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'todays-shiftings.html'));
});

app.get('/new-reminder', isAuthenticated,checkRole('admin','user'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'new-reminder.html'));
});

app.get('/total-sales', isAuthenticated,checkRole('admin','user'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'total-sales.html'));
});

app.get('/calendar', isAuthenticated,checkRole('admin','user'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'calendar.html'));
});


app.get('/view-all-appointments', isAuthenticated,checkRole('admin','user'), (req, res, next) => {
  console.log('Request received for /view-all-appointments');
  res.sendFile(path.join(__dirname, 'views', 'view-all-appointments.html'), (err) => {
    if (err) {
      console.error('Error sending file:', err);
      next(err); // Pass errors to the error handler
    } else {
      console.log('view-all-appointments.html served successfully');
    }
  });
});

app.get('/check-session', (req, res) => {
  if (req.session.user) {
    res.status(200).json({ session: req.session });
  } else {
    res.status(401).json({ message: 'Not authenticated' });
  }
});

app.get('/user-action-logs', isAuthenticated, checkRole('admin'), (req, res) => {
  fs.readFile('userActionLogs.json', (err, data) => {
    if (err) {
      res.status(500).json({ message: 'Error reading user action logs' });
    } else {
      res.status(200).json(JSON.parse(data));
    }
  });
});

app.get('/chat-logs', isAuthenticated, checkRole('admin'), (req, res) => {
  const chatLogsArray = Object.values(chatLogs).map(log => ({
    customerName: log.customerName,
    messages: log.messages,
    timestamp: new Date() // assuming the timestamp is the time the log was created; modify as needed
  }));
  res.status(200).json(chatLogsArray);
});

app.get('/staff', isAuthenticated, checkRole('admin','staff'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'staff.html'));
});
// Function to log chat messages
const logChatMessage = async (appointmentId, message, customerName) => {
  const query = `
    INSERT INTO chat_logs (appointment_id, customer_name, message, timestamp)
    VALUES ($1, $2, $3, $4)
  `;
  const values = [appointmentId, customerName, message, new Date()];
  await pool.query(query, values);
};

app.get('/api/bookings', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        date_trunc('day', date) as date,
        COUNT(*) FILTER (WHERE type_of_booking = 'local' AND status = 'booked') AS local_count,
        COUNT(*) FILTER (WHERE type_of_booking = 'intercity' AND status = 'booked') AS intercity_count
      FROM 
        appointments
      WHERE 
        status = 'booked'
      GROUP BY 
        date_trunc('day', date)
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



// Function to send message
const sendMessage = (method, to, contentSid, contentVariables) => {
  return twilioClient.messages.create({
    from: method === 'whatsapp' ? whatsappPhoneNumber : twilioPhoneNumber, // Your Twilio WhatsApp number or SMS number
    to: method === 'whatsapp' ? `whatsapp:${to}` : to,
    messagingServiceSid,
    contentSid,
    contentVariables: JSON.stringify(contentVariables)
  });
};

// Helper Functions for Sales Reports
async function getDailySales() {
  const query = `
    SELECT DATE(appointment_date) as date, SUM(total_booking_cost) as totalSales
    FROM appointments
    WHERE status = 'completed'
    GROUP BY DATE(appointment_date)
    ORDER BY date;
  `;
  const { rows } = await pool.query(query);
  return rows;
}

async function getWeeklySales() {
  const query = `
    SELECT DATE_TRUNC('week', appointment_date) as week, SUM(total_booking_cost) as totalSales
    FROM appointments
    WHERE status = 'completed'
    GROUP BY DATE_TRUNC('week', appointment_date)
    ORDER BY week;
  `;
  const { rows } = await pool.query(query);
  return rows;
}

async function getMonthlySales() {
  const query = `
    SELECT DATE_TRUNC('month', appointment_date) as month, SUM(total_booking_cost) as totalSales
    FROM appointments
    WHERE status = 'completed'
    GROUP BY DATE_TRUNC('month', appointment_date)
    ORDER BY month;
  `;
  const { rows } = await pool.query(query);
  return rows;
}

// Helper Functions for Reports
async function getOverallReports(period) {
  const query = `
    SELECT
      COUNT(*) FILTER (WHERE status IS NOT NULL) AS totalAppointments,
      COUNT(*) FILTER (WHERE status = 'booked') AS bookedAppointments,
      COUNT(*) FILTER (WHERE status = 'completed') AS completedAppointments,
      COUNT(*) FILTER (WHERE status != 'booked' AND status != 'completed') AS notBookedAppointments
    FROM appointments
  `;
  const { rows } = await pool.query(query);
  return rows[0];
}

async function getSalesReports(period) {
  let query;
  if (period === 'daily') {
    query = `
      SELECT DATE(appointment_date) AS date, SUM(total_booking_cost) AS totalSales
      FROM appointments
      WHERE status = 'completed'
      GROUP BY DATE(appointment_date)
      ORDER BY date;
    `;
  } else if (period === 'weekly') {
    query = `
      SELECT DATE_TRUNC('week', appointment_date) AS week, SUM(total_booking_cost) AS totalSales
      FROM appointments
      WHERE status = 'completed'
      GROUP BY DATE_TRUNC('week', appointment_date)
      ORDER BY week;
    `;
  } else if (period === 'monthly') {
    query = `
      SELECT DATE_TRUNC('month', appointment_date) AS month, SUM(total_booking_cost) AS totalSales
      FROM appointments
      WHERE status = 'completed'
      GROUP BY DATE_TRUNC('month', appointment_date)
      ORDER BY month;
    `;
  }
  const { rows } = await pool.query(query);
  return rows;
}

async function getDriverSchedules(period) {
  const query = `
    SELECT ds.driver_id, d.name AS driver_name, a.name AS customer_name, a.address_from, a.address_to, a.phone AS customer_phone, ds.date
    FROM driver_schedules ds
    JOIN drivers d ON ds.driver_id = d.id
    JOIN appointments a ON ds.appointment_id = a.id
    WHERE ds.date >= NOW() - INTERVAL '1 ${period}' AND ds.date <= NOW()
    ORDER BY ds.date;
  `;
  const { rows } = await pool.query(query);
  return rows;
}

// Webhook for processing user responses
app.post('/webhook', async (req, res) => {
  const message = req.body.Body.toLowerCase();
  const from = req.body.From;

  if (message === 'yes') {
    const result = await pool.query(
      'SELECT * FROM appointments WHERE phone = $1 LIMIT 1',
      [from.replace('whatsapp:', '')]
    );
    const appointment = result.rows[0];
    if (appointment) {
      if (appointment.status === 'saved') {
        await pool.query(
          'UPDATE appointments SET status = $1 WHERE id = $2',
          ['assigned', appointment.id]
        );
        sendMessage('whatsapp', appointment.phone, templates.bookingConfirmed, { "1": appointment.name })
          .then(message => console.log(`Assignment message sent to customer: ${message.sid}`))
          .catch(error => console.error('Error sending assignment message:', error));
      } else if (appointment.status === 'booked') {
        sendMessage('whatsapp', appointment.phone, templates.bookingConfirmed, { "1": appointment.name })
          .then(message => console.log(`Booking confirmation message sent to customer: ${message.sid}`))
          .catch(error => console.error('Error sending booking confirmation message:', error));
      }
    }
  } else if (message === 'no') {
    sendMessage('whatsapp', from, templates.shiftingCompleted, { "1": "Thank you for doing business with us! We hope you enjoy your new place." })
      .then(message => console.log(`No message response sent to customer: ${message.sid}`))
      .catch(error => console.error('Error sending no message response:', error));
  }
  res.sendStatus(200);
});

app.post('/appointments', isAuthenticated, async (req, res) => {
  const { id, name, phone, addressFrom, addressTo, date, branch, shiftingDate, communicationMethod, type_of_booking } = req.body;

  if (id) {
    const result = await pool.query('SELECT * FROM appointments WHERE id = $1', [id]);
    const appointment = result.rows[0];
    if (appointment) {
      if (
        appointment.name === name &&
        appointment.phone === phone &&
        appointment.address_from === addressFrom &&
        appointment.address_to === addressTo &&
        appointment.date === date &&
        appointment.branch === branch &&
        appointment.shifting_date === shiftingDate &&
        appointment.type_of_booking === type_of_booking
      ) {
        res.status(200).json({ message: 'No changes detected' });
      } else {
        await pool.query(
          `UPDATE appointments SET name = $1, phone = $2, address_from = $3, address_to = $4, date = $5, branch = $6, shifting_date = $7, type_of_booking = $8
           WHERE id = $9`,
          [name, phone, addressFrom, addressTo, date, branch, shiftingDate, type_of_booking, id]
        );
        res.status(200).json({ message: 'Appointment updated' });
      }
    } else {
      res.status(404).send('Appointment not found!');
    }
  } else {
    const result = await pool.query(
      `INSERT INTO appointments (name, phone, address_from, address_to, date, branch, status, shifting_date, communication_method, assigned_time, type_of_booking)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
      [name, phone, addressFrom, addressTo, date, branch, 'assigned', shiftingDate, communicationMethod, new Date(), type_of_booking]
    );
    const newAppointmentId = result.rows[0].id;
    res.status(201).send('Appointment added!');

    // Send welcome message to customer
    sendMessage(communicationMethod, phone, templates.welcome, { "1": name })
      .then(message => {
        console.log(`Welcome message sent to customer: ${message.sid}`);
        // Send appointment created message to customer
        return sendMessage(communicationMethod, phone, templates.appointmentCreated, { "1": name });
      }).then(message => {
        console.log(`Appointment created message sent to customer: ${message.sid}`);
      }).catch(error => {
        console.error('Error sending messages to customer:', error);
      });

    // Send SMS to owner
    twilioClient.messages.create({
      body: `New appointment confirmed for ${name} from ${addressFrom} to ${addressTo} on ${date}.`,
      from: twilioPhoneNumber,
      to: ownerNumber
    }).then(message => console.log(`Message sent to owner: ${message.sid}`)).catch(error => console.error(error));

    // Send SMS to sales person
    const salesNumber = salesNumbers[branch];
    if (salesNumber) {
      twilioClient.messages.create({
        body: `New appointment confirmed for ${name} from ${addressFrom} to ${addressTo} on ${date}.`,
        from: twilioPhoneNumber,
        to: salesNumber
      }).then(message => console.log(`Message sent to sales person: ${message.sid}`)).catch(error => console.error(error));
    }
  }
});

// Sorting logic
// Get all appointments with driver details
app.get('/appointments', isAuthenticated, async (req, res) => {
  try {
    const query = `
      SELECT a.*, d.name as driver_name
      FROM appointments a
      LEFT JOIN driver_schedules ds ON a.id = ds.appointment_id
      LEFT JOIN drivers d ON ds.driver_id = d.id
      ORDER BY a.id DESC
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching appointments with driver details:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/appointments/:id', isAuthenticated, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const result = await pool.query('SELECT * FROM appointments WHERE id = $1', [id]);
  const appointment = result.rows[0];
  if (appointment) {
    console.log(`Retrieved appointment: ${JSON.stringify(appointment)}`); // Debug log
    // Format the date to remove the timestamp
    appointment.date = appointment.date.toISOString().split('T')[0];
    appointment.shifting_date = appointment.shifting_date ? appointment.shifting_date.toISOString().split('T')[0] : null;
    appointment.assigned_time = appointment.assigned_time ? appointment.assigned_time.toISOString() : null;
    res.status(200).json(appointment);
  } else {
    res.status(404).json({ message: 'Appointment not found!' });
  }
});

app.put('/appointments/:id', isAuthenticated,checkRole('admin','user'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { status, advancePayment, totalBookingCost, shiftingDate, advancePaymentMethod, balancePaymentMethod, notes, cancelReason } = req.body;
  const result = await pool.query('SELECT * FROM appointments WHERE id = $1', [id]);
  const appointment = result.rows[0];
  if (appointment) {
    if (appointment.status === 'completed') {
      res.status(400).json({ message: 'Cannot modify a completed appointment' });
    } else if (appointment.status === 'cancelled') {
      res.status(400).json({ message: 'Cannot modify a cancelled appointment' });
    } else if (appointment.status === 'not booked' && status !== 'not booked') {
      res.status(400).json({ message: 'Status cannot be changed from "Not Booked"' });
    } else {
      const updatedStatus = status || appointment.status;
      const updatedAdvancePayment = advancePayment !== undefined ? advancePayment : appointment.advance_payment;
      const updatedTotalBookingCost = totalBookingCost !== undefined ? totalBookingCost : appointment.total_booking_cost;
      const updatedShiftingDate = shiftingDate || appointment.shifting_date;
      const updatedAdvancePaymentMethod = advancePaymentMethod || appointment.advance_payment_method;
      const updatedBalancePaymentMethod = balancePaymentMethod || appointment.balance_payment_method;
      const updatedNotes = notes || appointment.notes;
      const updatedCancelReason = cancelReason || appointment.cancel_reason;

      await pool.query(
        `UPDATE appointments SET status = $1, advance_payment = $2, total_booking_cost = $3, shifting_date = $4,
         advance_payment_method = $5, balance_payment_method = $6, notes = $7, cancel_reason = $8 WHERE id = $9`,
        [updatedStatus, updatedAdvancePayment, updatedTotalBookingCost, updatedShiftingDate,
         updatedAdvancePaymentMethod, updatedBalancePaymentMethod, updatedNotes, updatedCancelReason, id]
      );

      if (status === 'booked') {
        // Send SMS to customer and owner with booking information
        if (appointment.communication_method === 'sms') {
          twilioClient.messages.create({
            body: `Dear ${appointment.name}, your booking is confirmed with advance payment of ${advancePayment}, total cost of ${totalBookingCost}, and shifting date on ${shiftingDate}.`,
            from: twilioPhoneNumber,
            to: appointment.phone
          }).then(message => console.log(`Booking message sent to customer: ${message.sid}`)).catch(error => console.error(error));
        } else {
          sendMessage('whatsapp', appointment.phone, templates.bookingConfirmed, { "1": appointment.name })
            .then(message => console.log(`Booking confirmation message sent to customer: ${message.sid}`))
            .catch(error => console.error('Error sending booking confirmation message:', error));
        }

        twilioClient.messages.create({
          body: `Booking confirmed for ${appointment.name} with advance payment of ${advancePayment}, total cost of ${totalBookingCost}, and shifting date on ${shiftingDate}.`,
          from: twilioPhoneNumber,
          to: ownerNumber
        }).then(message => console.log(`Booking message sent to owner: ${message.sid}`)).catch(error => console.error(error));
      }
      if (status === 'completed') {
        // Send SMS to customer confirming payment received
        if (appointment.communication_method === 'sms') {
          twilioClient.messages.create({
            body: `Thank you for doing business with us. Your payment has been received. We hope you are settling into your new place smoothly.`,
            from: twilioPhoneNumber,
            to: appointment.phone
          }).then(message => console.log(`Payment confirmation message sent to customer: ${message.sid}`)).catch(error => console.error(error));
        } else {
          sendMessage('whatsapp', appointment.phone, templates.shiftingCompleted, { "1": appointment.name })
            .then(message => console.log(`Payment confirmation message sent to customer: ${message.sid}`))
            .catch(error => console.error('Error sending payment confirmation message:', error));
        }

        // Send SMS to owner with all booking information
        const bookingInfo = `Booking Details:\nName: ${appointment.name}\nPhone: ${appointment.phone}\nFrom: ${appointment.address_from}\nTo: ${appointment.address_to}\nDate: ${appointment.date}\nBranch: ${appointment.branch}\nShifting Date: ${appointment.shifting_date}\nAdvance Payment: ${appointment.advance_payment}\nTotal Cost: ${appointment.total_booking_cost}\nAdvance Payment Method: ${appointment.advance_payment_method}\nBalance Payment Method: ${appointment.balance_payment_method}\nNotes: ${appointment.notes}`;
        twilioClient.messages.create({
          body: bookingInfo,
          from: twilioPhoneNumber,
          to: ownerNumber
        }).then(message => console.log(`Booking info message sent to owner: ${message.sid}`)).catch(error => console.error(error));
      }
      if (status === 'cancelled') {
        // Send SMS to customer and owner with cancellation information
        const cancelMessage = `Dear ${appointment.name}, your booking has been cancelled. Reason: ${cancelReason}`;
        if (appointment.communication_method === 'sms') {
          twilioClient.messages.create({
            body: cancelMessage,
            from: twilioPhoneNumber,
            to: appointment.phone
          }).then(message => console.log(`Cancellation message sent to customer: ${message.sid}`)).catch(error => console.error(error));
        } else {
          sendMessage('whatsapp', appointment.phone, cancelMessage)
            .then(message => console.log(`Cancellation message sent to customer: ${message.sid}`))
            .catch(error => console.error('Error sending cancellation message:', error));
        }

        twilioClient.messages.create({
          body: `Booking for ${appointment.name} has been cancelled. Reason: ${cancelReason}`,
          from: twilioPhoneNumber,
          to: ownerNumber
        }).then(message => console.log(`Cancellation message sent to owner: ${message.sid}`)).catch(error => console.error(error));
      }
      res.status(200).json({ message: 'Status, amounts, and shifting date updated!' });
    }
  } else {
    res.status(404).json({ message: 'Appointment not found!' });
  }
});

app.get('/appointments', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM appointments');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Handle reminders
app.post('/reminders', isAuthenticated, async (req, res) => {
  const { reminder, flag, date, completed } = req.body;
  const result = await pool.query(
    'INSERT INTO reminders (reminder, flag, date, completed) VALUES ($1, $2, $3, $4) RETURNING *',
    [reminder, flag, date, completed || false]
  );
  const newReminder = result.rows[0];
  res.status(201).json({ message: 'Reminder added!', reminder: newReminder });
});

app.get('/reminders', isAuthenticated, async (req, res) => {
  const result = await pool.query('SELECT * FROM reminders WHERE completed = false');
  res.json(result.rows);
});

app.put('/reminders/:id', isAuthenticated, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { completed } = req.body;
  const result = await pool.query(
    'UPDATE reminders SET completed = $1 WHERE id = $2 RETURNING *',
    [completed, id]
  );
  const reminder = result.rows[0];
  if (reminder) {
    res.status(200).json({ message: 'Reminder status updated!', reminder });
  } else {
    res.status(404).json({ message: 'Reminder not found!' });
  }
});

// OTP and Login Logic
const users = [
  { username: 'sudheerg', password: 'bunny', email: 'support@cpm.com', role: 'admin', backupCode: 'ABC123' },
  { username: 'sunny', password: 'sunny', email: 'sunny@cpm.com', role: 'user', backupCode: 'XYZ789' },
  { username: 'ramu ', password: 'ramu123', email: 'staff1@cpm.com', role: 'staff', backupCode: 'STAFF123' }
];


otpStorage = {}; // Remove the duplicate declaration

// Send OTP
app.post('/send-otp', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const user = users.find(user => user.email === email && user.password === password);
  if (!user) {
    return res.status(400).json({ message: 'Invalid email or password' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStorage[email] = otp;

  console.log(`OTP for ${email}: ${otp}`); // Log OTP to terminal for testing

  const clientIp = req.ip;
  const deviceInfo = `${req.useragent.os} - ${req.useragent.browser}`;

  // Send OTP via SMS using Twilio
  twilioClient.messages.create({
    body: `Your OTP code is: ${otp}\nIP: ${clientIp}\nDevice: ${deviceInfo}`,
    from: twilioPhoneNumber,
    to: ownerNumber // Send OTP to owner's number
  }).then(message => {
    console.log('OTP sent via SMS:', message.sid);
    req.session.tempUser = user; // Save user info in session
    res.render('otp', { email, error: null });
  }).catch(error => {
    console.error('Error sending OTP via SMS:', error);
    req.session.tempUser = user; // Save user info in session
    res.render('backup-code', { email, error: 'Failed to send OTP. Please use your backup code.' });
  });
});

// Verify OTP or Backup Code
app.post('/verify-otp', (req, res) => {
  const { email, otpOrBackupCode } = req.body;
  console.log(`Verifying OTP/Backup Code for ${email}: ${otpOrBackupCode}`); // Log OTP/Backup Code verification attempt
  const user = users.find(user => user.email === email);

  if (user && (otpStorage[email] && otpStorage[email] == otpOrBackupCode || user.backupCode === otpOrBackupCode)) {
    req.session.user = req.session.tempUser; // Set the authenticated user
    delete req.session.tempUser;
    delete otpStorage[email];

        // Redirect based on role
    if (user.role === 'staff') {
      res.redirect('/staff');
    } else if (user.role === 'admin') {
      res.redirect('/index');
    } else {
      res.redirect('/index');
    }
  } else {
    console.log(`Invalid OTP/Backup Code for ${email}`); // Log invalid OTP/Backup Code attempt
    res.render('backup-code', { email, error: 'Invalid OTP or Backup Code' });
  }
});



// Login route
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(user => user.email === email && user.password === password);
  if (user) {
    req.session.email = email;
    req.session.tempUser = user;
    console.log('User logged in:', user); // Debug log
    res.redirect('/otp');
  } else {
    console.log('Invalid credentials'); // Debug log
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

// Local Driver Assignment
app.post('/assign-local-driver', isAuthenticated, checkRole('admin','user'),async (req, res) => {
  const { appointmentId, driverName } = req.body;
  const result = await pool.query('SELECT * FROM appointments WHERE id = $1', [parseInt(appointmentId, 10)]);
  const appointment = result.rows[0];
  if (appointment) {
    const driverNumber = {
      'Ravi': process.env.DRIVER_NUMBER_RAVI,
      'chintu': process.env.DRIVER_NUMBER_CHINTU,
      'Ravi2': process.env.DRIVER_NUMBER_RAVI2,
      'chintu2': process.env.DRIVER_NUMBER_CHINTU2
    }[driverName];

    const ownerMessage = `${driverName} has been assigned for shifting on ${appointment.shifting_date} for ${appointment.name}, from ${appointment.address_from} to ${appointment.address_to}`;
    const customerMessage = `${driverName} has been assigned as a driver for your shifting on ${appointment.shifting_date}. Here is the driver contact: ${driverNumber}`;
    const driverMessage = `You are scheduled to shift from ${appointment.address_from} to ${appointment.address_to} for ${appointment.name} on ${appointment.shifting_date}`;

    // Send messages to owner, customer, and driver
    twilioClient.messages.create({
      body: ownerMessage,
      from: twilioPhoneNumber,
      to: ownerNumber
    }).then(message => {
      console.log(`Local driver assignment message sent to owner: ${message.sid}`);
      logChatMessage(appointmentId, ownerMessage, appointment.name);
    }).catch(error => {
      console.error(error);
    });

    twilioClient.messages.create({
      body: customerMessage,
      from: twilioPhoneNumber,
      to: appointment.phone
    }).then(message => {
      console.log(`Local driver assignment message sent to customer: ${message.sid}`);
      logChatMessage(appointmentId, customerMessage, appointment.name);
    }).catch(error => console.error(error));

    twilioClient.messages.create({
      body: driverMessage,
      from: twilioPhoneNumber,
      to: driverNumber
    }).then(message => {
      console.log(`Local driver assignment message sent to driver: ${message.sid}`);
      logChatMessage(appointmentId, driverMessage, appointment.name);
    }).catch(error => console.error(error));

    res.status(200).json({ message: 'Local driver assigned successfully' });
  } else {
    res.status(404).json({ message: 'Appointment not found!' });
  }
});

// Send to Driver
app.post('/send-to-driver', isAuthenticated, async (req, res) => {
  const { appointmentId, driverName, driverNumber, notes } = req.body;
  const result = await pool.query('SELECT * FROM appointments WHERE id = $1', [parseInt(appointmentId, 10)]);
  const appointment = result.rows[0];
  if (appointment) {
    const customerMessage = `${driverName} has been assigned as a driver for your shifting on ${appointment.shifting_date}. Here is the driver contact: ${driverNumber}`;
    const ownerMessage = `${driverName} has been assigned for shifting on ${appointment.shifting_date} for ${appointment.name}, from ${appointment.address_from} to ${appointment.address_to}. Notes: ${notes}`;
    const driverMessage = `You are scheduled to shift from ${appointment.address_from} to ${appointment.address_to} for ${appointment.name} on ${appointment.shifting_date}. Notes: ${notes}`;

    twilioClient.messages.create({
      body: customerMessage,
      from: twilioPhoneNumber,
      to: appointment.phone
    }).then(message => console.log(`Send to driver message sent to customer: ${message.sid}`)).catch(error => console.error(error));

    twilioClient.messages.create({
      body: ownerMessage,
      from: twilioPhoneNumber,
      to: ownerNumber
    }).then(message => console.log(`Send to driver message sent to owner: ${message.sid}`)).catch(error => console.error(error));

    twilioClient.messages.create({
      body: driverMessage,
      from: twilioPhoneNumber,
      to: driverNumber
    }).then(message => console.log(`Send to driver message sent to driver: ${message.sid}`)).catch(error => console.error(error));

    res.status(200).json({ message: 'Message sent to driver successfully' });
  } else {
    res.status(404).json({ message: 'Appointment not found' });
  }
});

// Send Review Link
app.post('/send-review-link', isAuthenticated, async (req, res) => {
  const { appointmentId } = req.body;
  const result = await pool.query('SELECT * FROM appointments WHERE id = $1', [appointmentId]);
  const appointment = result.rows[0];
  if (appointment) {
    const reviewLink = 'https://shorturl.at/bNNAj';
    const reviewMessage = `Please leave a review for our services: ${reviewLink}`;

    twilioClient.messages.create({
      body: reviewMessage,
      from: twilioPhoneNumber,
      to: appointment.phone
    }).then(message => {
      logChatMessage(appointmentId, message.body, appointment.name);
      res.status(200).json({ message: 'Review link sent successfully' });
    }).catch(error => {
      console.error('Error sending review link:', error);
      res.status(500).json({ message: 'Error sending review link' });
    });
  } else {
    res.status(404).json({ message: 'Appointment not found' });
  }
});

// Chat with Customer
app.post('/chat-with-customer', isAuthenticated, (req, res) => {
  const { phoneNumber, message } = req.body;
  if (phoneNumber && message) {
    twilioClient.messages.create({
      body: message,
      from: twilioPhoneNumber,
      to: phoneNumber
    }).then(message => {
      logChatMessage(null, message.body, 'Customer');
      res.status(200).json({ message: 'Chat message sent successfully' });
    }).catch(error => {
      console.error('Error sending chat message:', error);
      res.status(500).json({ message: 'Error sending chat message' });
    });
  } else {
    res.status(400).json({ message: 'Phone number and message are required' });
  }
});

// Update Settings
app.get('/settings-data', isAuthenticated, checkRole('admin'), (req, res) => {
  fs.readFile(settingsPath, (err, data) => {
    if (err) {
      return res.status(500).json({ message: 'Error reading settings' });
    }
    res.status(200).json(JSON.parse(data));
  });
});

app.post('/update-settings', isAuthenticated, checkRole('admin'), (req, res) => {
  const newSettings = req.body;
  fs.writeFile(settingsPath, JSON.stringify(newSettings, null, 2), (err) => {
    if (err) {
      return res.status(500).json({ message: 'Error updating settings' });
    }
    res.status(200).json({ message: 'Settings updated successfully' });
  });
});

app.post('/submitNotBookedReason', (req, res) => {
  const { reason } = req.body;

  console.log("Reason received:", reason);
  res.status(200).json({ message: 'Reason received successfully.' });
});

// Handle Sales reports
app.get('/sales-reports', isAuthenticated,checkRole('admin'), async (req, res) => {
  const { period } = req.query;
  try {
    let salesData;
    if (period === 'daily') {
      salesData = await getDailySales();
    } else if (period === 'weekly') {
      salesData = await getWeeklySales();
    } else if (period === 'monthly') {
      salesData = await getMonthlySales();
    } else {
      return res.status(400).json({ error: 'Invalid period specified' });
    }
    res.json(salesData);
  } catch (error) {
    console.error('Error fetching sales reports:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Delete appointments from the database
app.delete('/appointments/:id', isAuthenticated, checkRole('admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const result = await pool.query('DELETE FROM appointments WHERE id = $1', [id]);
  if (result.rowCount > 0) {
    res.status(200).json({ message: 'Appointment deleted!' });
  } else {
    res.status(404).json({ message: 'Appointment not found!' });
  }
});

// Fetch the logged-in user's username
app.get('/get-username', (req, res) => {
  if (req.session.user) {
    res.json({ username: req.session.user.username });
  } else {
    res.status(401).json({ message: 'User not logged in' });
  }
});

// DRIVER SIDE LOGIC ////
// Get all drivers
app.get('/drivers', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM drivers');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching drivers:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Add a driver
app.post('/drivers', isAuthenticated,checkRole('admin','user'), async (req, res) => {
  const { name, phone } = req.body;
  try {
    await pool.query('INSERT INTO drivers (name, phone) VALUES ($1, $2)', [name, phone]);
    res.json({ message: 'Driver added successfully' });
  } catch (err) {
    console.error('Error adding driver:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a driver
app.delete('/drivers/:id', isAuthenticated,checkRole('admin') ,async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM drivers WHERE id = $1', [id]);
    res.json({ message: 'Driver deleted successfully' });
  } catch (err) {
    console.error('Error deleting driver:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all driver schedules
app.get('/driver-schedules', async (req, res) => {
  const { driver_id, date } = req.query;

  // Initialize the query and parameters array
  let query = 'SELECT * FROM driver_schedules WHERE 1=1';
  let params = [];

  // Add filtering conditions based on provided query parameters
  if (driver_id) {
    query += ' AND driver_id = $1';
    params.push(driver_id);
  }
  if (date) {
    query += params.length ? ' AND date = $2' : ' AND date = $1';
    params.push(date);
  }

  try {
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching driver schedules:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/driver-schedules', async (req, res) => {
  const { driver_id, date, time_slot, appointment_id } = req.body;

  // Validate inputs
  if (!driver_id || !date || !time_slot || !appointment_id) {
    return res.status(400).json({ error: 'Please fill in all details to add a schedule.' });
  }

  try {
    // Check if the appointment is already assigned to another driver
    const existingSchedule = await pool.query(
      'SELECT * FROM driver_schedules WHERE appointment_id = $1',
      [appointment_id]
    );

    if (existingSchedule.rows.length > 0) {
      return res.status(400).json({ error: 'This appointment is already assigned to a driver.' });
    }

    // Check if the appointment status is 'booked'
    const appointment = await pool.query(
      'SELECT * FROM appointments WHERE id = $1',
      [appointment_id]
    );

    if (appointment.rows.length === 0) {
      return res.status(404).json({ error: 'Appointment not found.' });
    }

    if (appointment.rows[0].status !== 'booked') {
      return res.status(400).json({ error: 'To schedule a driver, the appointment status needs to be "booked".' });
    }

    // Check if the shifting date and scheduling date are the same
    const shiftingDate = appointment.rows[0].shifting_date;
    if (new Date(shiftingDate).toISOString().split('T')[0] !== date) {
      return res.status(400).json({ error: 'The shifting date and scheduling date are not the same.' });
    }

    // Add the new driver schedule
    await pool.query(
      'INSERT INTO driver_schedules (driver_id, date, time_slot, appointment_id) VALUES ($1, $2, $3, $4)',
      [driver_id, date, time_slot, appointment_id]
    );

    res.json({ message: 'Driver schedule added successfully.' });
  } catch (error) {
    console.error('Error adding schedule:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Delete a driver schedule
app.delete('/driver-schedules/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM driver_schedules WHERE id = $1', [id]);
    res.json({ message: 'Schedule deleted successfully' });
  } catch (err) {
    console.error('Error deleting schedule:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Serve manage-schedules.html
app.get('/manage-schedules', isAuthenticated, checkRole('admin','user'),(req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'manage_schedules.html'));
});

// Route for overall reports
app.get('/overall-reports', isAuthenticated, async (req, res) => {
  const { period } = req.query;
  try {
    const overallReports = await getOverallReports(period);
    res.json(overallReports);
  } catch (error) {
    console.error('Error fetching overall reports:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Route for sales reports
app.get('/sales-reports', isAuthenticated, async (req, res) => {
  const { period } = req.query;
  try {
    const salesReports = await getSalesReports(period);
    res.json(salesReports);
  } catch (error) {
    console.error('Error fetching sales reports:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Route for driver schedules
app.get('/driver-schedules', isAuthenticated, async (req, res) => {
  const { period } = req.query;
  try {
    const driverSchedules = await getDriverSchedules(period);
    res.json(driverSchedules);
  } catch (error) {
    console.error('Error fetching driver schedules:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Handle 404 errors
app.use((req, res, next) => {
  res.status(404).render('404');
});

// Start server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
