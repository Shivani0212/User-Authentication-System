# User-Authentication-System 

A secure authentication system built with **Node.js, Express, and MongoDB**, implementing **JWT-based authentication** with **user registration, login, and password reset functionality**.

## **Features**
- **User Registration** (with password hashing)  
- **JWT-based Authentication** (Login & Protected Routes)  
- **Password Reset** (Token-based)  
- **Input Validation & Error Handling**  

## **Tech Stack**
- **Backend:** Node.js, Express.js  
- **Database:** MongoDB (Mongoose ORM)  
- **Authentication:** JWT, Bcrypt  
- **Email Service:** Nodemailer
-  
```bash
### **1.Clone the repository**
    git clone https://github.com/Shivani0212/User-Authentication-System.git
    cd user-auth-system

### **2.Install dependencies**
    npm install

### **3.Create a .env file**
    MONGO_URI
    JWT_SECRET

### **4.Start the server**
    npm run server
