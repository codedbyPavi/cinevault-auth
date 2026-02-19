# Auth App – Registration & Login

A beginner-friendly Registration and Login web application built with **Node.js**, **Express**, and **MySQL**. Passwords are hashed with bcrypt; the server creates the `users` table automatically on start.

---

## Run instructions

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Set database credentials**  
   Edit `db.js` and replace the placeholder values for:
   - `DB_HOST`
   - `DB_USER`
   - `DB_PASSWORD`
   - `DB_NAME`
   - `DB_PORT`  

   Or set them as environment variables (e.g. for Aiven cloud):
   ```bash
   set DB_HOST=your-host
   set DB_USER=your-user
   set DB_PASSWORD=your-password
   set DB_NAME=your-database
   set DB_PORT=3306
   ```

3. **Start the server**
   ```bash
   node server.js
   ```

4. **Use the app**  
   - Open: **http://localhost:3000/register.html** to register  
   - Open: **http://localhost:3000/login.html** to log in  

   On successful login you are redirected to: https://netflix-landing-eta.vercel.app/

---

## Project structure

```
server.js          # Express app, routes, server start
db.js              # MySQL connection and users table creation
package.json
public/
  register.html    # Registration page
  login.html       # Login page
  style.css        # Shared styles (gradient/glass UI)
  script.js        # Form submit and API calls
```

---

## Tech stack

- **Backend:** Node.js, Express, MySQL2, bcrypt, cors, body-parser  
- **Frontend:** HTML, CSS, vanilla JS; gradient/glass-style UI  

---

## Database

- **Table:** `users`  
- The table is created automatically when the server starts (see `db.js`: `CREATE TABLE IF NOT EXISTS users ...`).  
- Columns: `id`, `user_id`, `name`, `email`, `phone`, `password` (hashed), `created_at`.

---

## API

- **POST /api/register**  
  Body: `user_id`, `name`, `email`, `phone`, `password`  
  Response: `{ success, message }`

- **POST /api/login**  
  Body: `loginId` (User ID or Email), `password`  
  Response: `{ success, message }`  
  On success, the frontend redirects to the Netflix landing URL.

---

*For educational use; replace placeholder DB credentials before running with a real database (e.g. Aiven MySQL).*
