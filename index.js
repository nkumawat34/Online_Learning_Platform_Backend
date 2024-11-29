require('dotenv').config(); // Load environment variables
const { Client } = require('pg'); // PostgreSQL client
const express = require('express'); // Express framework
const bcrypt = require('bcrypt'); // Password hashing
const jwt = require('jsonwebtoken'); // JWT for token generation

const app = express(); // Initialize Express
app.use(express.json()); // Parse JSON requests

// Database connection setup
const con = new Client({
  host: process.env.HOST,
  user: process.env.USER,
  port: process.env.DATABASE_PORT,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
});

con.connect()
  .then(() => console.log("Connected to Database"))
  .catch((err) => console.error("Database connection error:", err.message));

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

// Helper function to generate JWT
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET_KEY, { expiresIn: '7d' });
};

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Access Denied: No Token Provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET_KEY);
    req.user = decoded; // Attach user info to request
    next(); // Continue to the next middleware
  } catch (err) {
    res.status(403).json({ message: 'Invalid or Expired Token' });
  }
};

// =======================
// User Registration API
// =======================
app.post('/api/users/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'All fields are required' });

  try {
    const userCheck = await con.query('SELECT * FROM Users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) return res.status(400).json({ error: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = await con.query(
      'INSERT INTO Users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
      [name, email, hashedPassword, role]
    );

    res.status(201).json({ message: 'User registered successfully', user: newUser.rows[0] });
  } catch (error) {
    console.error("Registration error:", error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// =======================
// User Login API
// =======================
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'All fields are required' });

  try {
    const user = await con.query('SELECT * FROM Users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.rows[0].password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = generateToken(user.rows[0].id);
    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// =======================
// Add Course API
// =======================
app.post('/api/courses', verifyToken, async (req, res) => {
  const { title, description, instructor_id } = req.body;
  if (!title || !instructor_id) return res.status(400).json({ error: 'Title and Instructor ID are required' });

  try {
    const newCourse = await con.query(
      'INSERT INTO Courses (title, description, instructor_id) VALUES ($1, $2, $3) RETURNING *',
      [title, description, instructor_id]
    );
    res.status(201).json({ message: 'Course added successfully', course: newCourse.rows[0] });
  } catch (error) {
    console.error("Add Course error:", error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// =======================
// Edit Course API
// =======================
app.put('/api/courses/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { title, description } = req.body;
  if (!title && !description) return res.status(400).json({ error: 'At least one field (title or description) must be provided' });

  try {
    const course = await con.query('SELECT * FROM Courses WHERE id = $1', [id]);
    if (course.rows.length === 0) return res.status(404).json({ error: 'Course not found' });

    const updatedCourse = await con.query(
      'UPDATE Courses SET title = COALESCE($1, title), description = COALESCE($2, description) WHERE id = $3 RETURNING *',
      [title, description, id]
    );
    res.status(200).json({ message: 'Course updated successfully', course: updatedCourse.rows[0] });
  } catch (error) {
    console.error("Edit Course error:", error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// =======================
// Delete Course API
// =======================
app.delete('/api/courses/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const course = await con.query('SELECT * FROM Courses WHERE id = $1', [id]);
    if (course.rows.length === 0) return res.status(404).json({ error: 'Course not found' });

    await con.query('DELETE FROM Courses WHERE id = $1', [id]);
    res.status(200).json({ message: 'Course deleted successfully' });
  } catch (error) {
    console.error("Delete Course error:", error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// =======================
// Get All Courses for a Specific Instructor
// =======================
app.get('/api/courses/:instructorId', async (req, res) => {
  const { instructorId } = req.params;
  try {
    const courses = await con.query('SELECT * FROM Courses WHERE instructor_id = $1', [instructorId]);
    res.status(200).json({ courses: courses.rows });
  } catch (error) {
    console.error("Get Courses error:", error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Enroll in Course API
app.post('/api/enrollments', verifyToken,async (req, res) => {
  const { courseId, userId } = req.body;

  if (!courseId || !userId) {
    return res.status(400).json({ error: 'Course ID and User ID are required' });
  }

  try {
    // Check if the user is already enrolled in the course
    const existingEnrollment = await con.query(
      'SELECT * FROM Enrollments WHERE course_id = $1 AND user_id = $2',
      [courseId, userId]
    );

    if (existingEnrollment.rows.length > 0) {
      return res.status(400).json({ error: 'User is already enrolled in this course' });
    }

    // Enroll the student in the course
    const newEnrollment = await con.query(
      'INSERT INTO Enrollments (course_id, user_id) VALUES ($1, $2) RETURNING *',
      [courseId, userId]
    );

    res.status(201).json({
      message: 'Enrollment successful',
      enrollment: newEnrollment.rows[0],
    });
  } catch (error) {
    console.error('Enrollment error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Disenroll from Course API
app.delete('/api/enrollments',verifyToken, async (req, res) => {
  const { courseId, userId } = req.body;

  if (!courseId || !userId) {
    return res.status(400).json({ error: 'Course ID and User ID are required' });
  }

  try {
    // Check if the user is enrolled in the course
    const enrollment = await con.query(
      'SELECT * FROM Enrollments WHERE course_id = $1 AND user_id = $2',
      [courseId, userId]
    );

    if (enrollment.rows.length === 0) {
      return res.status(404).json({ error: 'Enrollment not found' });
    }

    // Remove the enrollment
    await con.query('DELETE FROM Enrollments WHERE course_id = $1 AND user_id = $2', [
      courseId,
      userId,
    ]);

    res.status(200).json({ message: 'Disenrollment successful' });
  } catch (error) {
    console.error('Disenrollment error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Enrolled Courses for a Student API
app.get('/api/enrollments/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    // Fetch the courses the user is enrolled in
    const enrollments = await con.query(
      'SELECT c.id, c.title, c.description, c.instructor_id FROM courses c JOIN Enrollments e ON c.id = e.course_id WHERE e.user_id = $1',
      [userId]
    );

    if (enrollments.rows.length === 0) {
      return res.status(404).json({ message: 'No enrolled courses found' });
    }

    res.status(200).json({ enrolledCourses: enrollments.rows });
  } catch (error) {
    console.error('Get Enrolled Courses error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit Feedback API
app.post('/api/courses/:courseId/reviews', async (req, res) => {
  const { courseId } = req.params;
  const { rating, comment, userId } = req.body;

  //console.log(rating)
  if (!courseId || !rating || !userId) {
    return res.status(400).json({ error: 'Course ID, Rating, and User ID are required' });
  }

  try {
    // Insert the feedback into the Reviews table
    const newReview = await con.query(
      'INSERT INTO Reviews (course_id, user_id, rating, comment) VALUES ($1, $2, $3, $4) RETURNING *',
      [courseId, userId, rating, comment]
    );

    res.status(201).json({
      message: 'Feedback submitted successfully',
      review: newReview.rows[0],
    });
  } catch (error) {
    console.error('Submit Feedback error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Review API
app.put('/api/courses/:courseId/reviews/:userId', async (req, res) => {
  const { courseId, userId } = req.params;
  const { rating, comment } = req.body;

  if (!rating && !comment) {
    return res.status(400).json({ error: 'At least one field (rating or comment) must be provided' });
  }

  try {
    // Check if the review exists
    const existingReview = await con.query(
      'SELECT * FROM Reviews WHERE course_id = $1 AND user_id = $2',
      [courseId, userId]
    );

    if (existingReview.rows.length === 0) {
      return res.status(404).json({ error: 'Review not found' });
    }

    // Update the review
    const updatedReview = await con.query(
      `UPDATE Reviews 
       SET rating = COALESCE($1, rating), 
           comment = COALESCE($2, comment)
       WHERE course_id = $3 AND user_id = $4
       RETURNING *`,
      [rating, comment, courseId, userId]
    );

    res.status(200).json({
      message: 'Review updated successfully',
      review: updatedReview.rows[0],
    });
  } catch (error) {
    console.error('Update Review error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Course Reviews API
app.get('/api/courses/:courseId/reviews', async (req, res) => {
  const { courseId } = req.params;

  try {
    // Retrieve all reviews for the given course ID
    const reviews = await con.query(
      'SELECT r.rating, r.comment, u.name AS reviewer_name FROM Reviews r JOIN Users u ON r.user_id = u.id WHERE r.course_id = $1',
      [courseId]
    );

    if (reviews.rows.length === 0) {
      return res.status(404).json({ message: 'No reviews found for this course' });
    }

    res.status(200).json({ reviews: reviews.rows });
  } catch (error) {
    console.error('Get Course Reviews error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start the server
const PORT = process.env.SERVER_PORT || 3000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}...`));
