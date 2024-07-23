import dotenv from 'dotenv';
import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import pool from './config/db.js'; 

// 파일의 현재 디렉토리를 구하기 위해 필요합니다.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

// CORS
app.use(cors({
    origin: process.env.CLIENT_URL,
    optionsSuccessStatus: 200,
    credentials: true,
}));

const encryptedPW = bcrypt.hashSync(process.env.ADMIN_PW, 8);

// 로그인
app.post('/login', async (req, res) => {
    try {
        if ((process.env.ADMIN_ID === req.body.id) && (bcrypt.compareSync(req.body.pw, encryptedPW))) {
            const payload = { userId: req.body.id };
            const secretKey = process.env.JWT_SECRET;
            const token = jwt.sign(payload, secretKey, { expiresIn: "1200m" });
            res.cookie('token', token, { httpOnly: true, sameSite: "none", secure: true, maxAge: 34000000 });
            res.json({
                code: 200,
                message: "token is created",
                token: token
            });
        } else {
            throw new Error('아이디와 비밀번호를 확인해주세요');
        }
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// 쿠키 검증
app.get('/verifyToken', (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }
    const secretKey = process.env.JWT_SECRET;
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token!!' });
        }

        return res.json({ message: 'Token is valid', user: decoded });
    });
});

// 로그아웃
app.post('/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true, sameSite: "none", secure: true
    });
    res.json({ message: 'Logout successful' });
});

// 기본 이미지 설정
const getDefaultImage = () => {
    const defaultImagePath = path.join(__dirname, 'public', 'blackLogo.png');
    return fs.readFileSync(defaultImagePath);
};

// 파일 업로드
const upload = multer({ storage: multer.memoryStorage() });

app.post('/upload', upload.fields([
    { name: 'pdf', maxCount: 1 },
    { name: 'jpg', maxCount: 1 }
]), async (req, res) => {
    try {
        console.log(req.body);
        const { title, writer, content, date, pdfName } = req.body;
        const pdf = req.files['pdf'] ? req.files['pdf'][0].buffer : null;
        const jpg = req.files['jpg'] ? req.files['jpg'][0].buffer : getDefaultImage();

        const [result] = await pool.query(
            'INSERT INTO reference (title, writer, content, date, pdf, jpg, pdfName) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [title, writer, content, date, pdf, jpg, pdfName]
        );

        res.json({ message: '데이터가 성공적으로 업로드되었습니다', postId: result.insertId });
    } catch (err) {
        console.error('데이터베이스에 데이터 저장 오류:', err);
        res.status(500).json({ message: '서버 내부 오류' });
    }
});

// dataRoom으로 전체 데이터 보내기
app.get('/dataroom', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, title, date, jpg FROM reference');
        const formattedRows = rows.map(row => ({
            ...row,
            jpg: row.jpg ? row.jpg.toString('base64') : null
        }));
        res.json(formattedRows);
    } catch (err) {
        console.error('Error retrieving data from database:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// 쿼리 파라미터로 데이터 보내기
app.get('/reference', async (req, res) => {
    const id = parseInt(req.query.id, 10);

    try {
        const [rows] = await pool.query(
            `SELECT
                r1.id,
                r1.title,
                r1.writer,
                r1.content,
                r1.pdfName,
                r1.date,
                r1.pdf,
                r1.jpg,
                r2.id AS previous_id,
                r2.title AS previous_title,
                r3.id AS next_id,
                r3.title AS next_title
            FROM reference r1
            LEFT JOIN reference r2 ON r2.id = (
                SELECT MAX(id) FROM reference WHERE id < r1.id
            )
            LEFT JOIN reference r3 ON r3.id = (
                SELECT MIN(id) FROM reference WHERE id > r1.id
            )
            WHERE r1.id = ?`, [id]
        );

        if (rows.length === 0) {
            res.status(404).json({ message: 'Post not found' });
        } else {
            const row = rows[0];
            const response = {
                current: {
                    id: row.id,
                    title: row.title,
                    writer: row.writer,
                    content: row.content,
                    date: row.date,
                    pdf: row.pdf ? row.pdf.toString('base64') : null,
                    pdfName: row.pdfName
                },
                previous: { id: row.previous_id, title: row.previous_title },
                next: { id: row.next_id, title: row.next_title }
            };
            res.json(response);
        }
    } catch (err) {
        console.error('Error retrieving data from database:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// 파일 수정하기
app.patch('/fixref', upload.fields([
    { name: 'pdf', maxCount: 1 },
    { name: 'jpg', maxCount: 1 }
]), async (req, res) => {
    console.log(req.body);
    const id = parseInt(req.query.id, 10);
    const { title, writer, content, pdfName, keepPDF, keepJPG } = req.body;

    try {
        const [rows] = await pool.query('SELECT pdf, jpg, pdfName FROM reference WHERE id = ?', [id]);

        if (rows.length === 0) {
            res.status(404).json({ message: 'Post not found' });
            return;
        }

        const row = rows[0];
        const pdf = req.files['pdf'] ? req.files['pdf'][0].buffer : (keepPDF ? row.pdf : null);
        const jpg = req.files['jpg'] ? req.files['jpg'][0].buffer : (keepJPG ? row.jpg : getDefaultImage());
        const name = pdfName ? pdfName : (keepPDF ? row.pdfName : "");

        await pool.query(
            'UPDATE reference SET title = ?, writer = ?, content = ?, pdf = ?, jpg = ?, pdfName = ? WHERE id = ?',
            [title, writer, content, pdf, jpg, name, id]
        );
        res.json({ message: 'Data updated successfully' });
    } catch (err) {
        console.error('Error updating data in database:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// 데이터 삭제
app.delete('/delete', async (req, res) => {
    const id = parseInt(req.query.id, 10);

    if (isNaN(id)) {
        res.status(400).json({ message: 'Invalid ID' });
        return;
    }

    try {
        const [result] = await pool.query('DELETE FROM reference WHERE id = ?', [id]);
        if (result.affectedRows === 0) {
            res.status(404).json({ message: 'No record found with the provided ID' });
        } else {
            res.json({ message: 'Record deleted successfully' });
        }
    } catch (err) {
        console.error('Error deleting data from database:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

const port = 3001;
app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
});

export default app;
