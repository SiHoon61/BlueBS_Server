import pool from './db.js';

const initializeDatabase = async () => {
    const createTableQuery = `
    CREATE TABLE IF NOT EXISTS reference (
      id INT PRIMARY KEY AUTO_INCREMENT NOT NULL,
      title VARCHAR(255) NOT NULL,
      writer VARCHAR(255) NOT NULL,
      content TEXT NOT NULL,
      date VARCHAR(255),
      pdf LONGBLOB,
      jpg LONGBLOB,
      pdfName VARCHAR(255)
    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  `;

    try {
        const connection = await pool.getConnection();
        await connection.query(createTableQuery);
        connection.release();
        console.log('Table `reference` is initialized.');
    } catch (err) {
        console.error('Error initializing database:', err);
    }
};

export default initializeDatabase;
