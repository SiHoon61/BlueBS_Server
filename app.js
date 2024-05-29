require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

dotenv.config();

const app = express();
app.use(express.json());
const cookieParser = require('cookie-parser');

app.use(cookieParser());

const cors = require('cors');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({
    origin: 'http://10.114.10.20:3000',
    optionsSuccessStatus: 200,
    credentials: true,
}));

const encryptedPW = bcrypt.hashSync(process.env.ADMIN_PW, 8);
//로그인
app.post('/login', async (req, res) => {
    try {
        if ((process.env.ADMIN_ID === req.body.id) && (bcrypt.compareSync(req.body.pw, encryptedPW))) {
            const payload = { userId: req.body.id };
            const secretKey = process.env.JWT_SECRET;
            const token = jwt.sign(payload, secretKey, { expiresIn: "1200m" });
            res.cookie('token', token, { httpOnly: true, sameSite: "none", secure: true, maxAge: 36000 });
            res.json({
                code: 200,
                message: "token is created",
                token: token
            })
        }
        else {
            throw new Error('아이디와 비밀번호를 확인해주세요');
        }
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

//쿠키 검증
app.get('/verifyToken', (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }
    const secretKey = process.env.JWT_SECRET;
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }

        return res.json({ message: 'Token is valid', user: decoded });
    });
});

//로그아웃
app.post('/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true, sameSite: "none", secure: true
    });
    res.json({ message: 'Logout successful' });
});

const port = 5000;
app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})

//기본 이미지 설정
const getDefaultImage = () => {
    const defaultImagePath = path.join(__dirname, 'public', 'blackLogo.png');
    return fs.readFileSync(defaultImagePath);
};

//파일 업로드
const upload = multer({ storage: multer.memoryStorage() });
const db = new sqlite3.Database('bluebsDB.db', (err) => {
    if (err) {
        return console.error('Error opening database:', err.message);
    }
    console.log('Connected to the in-memory SQLite database.');
});

app.post('/upload', upload.fields([
    { name: 'pdf', maxCount: 1 },
    { name: 'jpg', maxCount: 1 }
]), (req, res) => {
    console.log(req.body);
    const { title, writer, content, date, pdfName } = req.body;
    const pdf = req.files['pdf'] ? req.files['pdf'][0].buffer : null;
    const jpg = req.files['jpg'] ? req.files['jpg'][0].buffer : getDefaultImage();

    const stmt = db.prepare('INSERT INTO reference (title, writer, content, date, pdf, jpg, pdfName) VALUES (?, ?, ?, ?, ?, ?, ?)');
    stmt.run(title, writer, content, date, pdf, jpg, pdfName, function (err) {
        if (err) {
            console.error('Error storing data in database:', err);
            res.status(500).json({ message: 'Internal server error' });
        } else {
            res.json({ message: 'Data uploaded successfully', postId: this.lastID });
        }
    });
    stmt.finalize();
});

//dataRoom으로 전체 데이터 보내기
app.get('/dataroom', (req, res) => {
    db.all('SELECT id, title, date, jpg FROM reference', [], (err, rows) => {
        if (err) {
            console.error('Error retrieving data from database:', err);
            res.status(500).json({ message: 'Internal server error' });
        } else {
            // jpg 필드를 base64 인코딩하여 전달
            const formattedRows = rows.map(row => ({
                ...row,
                jpg: row.jpg ? row.jpg.toString('base64') : null
            }));
            res.json(formattedRows);
        }
    });
});

//쿼리 파라미터로 데이터 보내기
app.get('/reference', (req, res) => {
    const id = parseInt(req.query.id, 10);

    const query = `
        WITH reference_with_navigation AS (
            SELECT
            id,
            title,
            writer,
            content,
            pdfName,
            date,
            LAG(id) OVER (ORDER BY id) AS previous_id,
            LAG(title) OVER (ORDER BY id) AS previous_title,
            LEAD(id) OVER (ORDER BY id) AS next_id,
            LEAD(title) OVER (ORDER BY id) AS next_title
        FROM reference
    )
    SELECT *
    FROM reference_with_navigation
    WHERE id = ?;
    `;

    db.get(query, [id], (err, row) => {
        if (err) {
            console.error('Error retrieving data from database:', err);
            res.status(500).json({ message: 'Internal server error' });
        } else if (!row) {
            res.status(404).json({ message: 'Post not found' });
        } else {
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
                previous:{ id: row.previous_id, title: row.previous_title },
                next: { id: row.next_id, title: row.next_title }
            };

            res.json(response);
        }
    });
});

//파일 수정하기
app.patch('/fixref', upload.fields([
    { name: 'pdf', maxCount: 1 },
    { name: 'jpg', maxCount: 1 }
]), (req, res) => {
    console.log(req.body);
    const id = parseInt(req.query.id, 10);
    const { title, writer, content, pdfName, keepPDF, keepJPG } = req.body;


    // 현재 데이터 가져오기
    db.get('SELECT pdf, jpg, pdfName FROM reference WHERE id = ?', [id], (err, row) => {
        if (err) {
            console.error('Error retrieving data from database:', err);
            res.status(500).json({ message: 'Internal server error' });
            return;
        }

        if (!row) {
            res.status(404).json({ message: 'Post not found' });
            return;
        }

        // 파일 업데이트 처리
        const pdf = req.files['pdf'] ? req.files['pdf'][0].buffer : (keepPDF ? row.pdf : null);
        const jpg = req.files['jpg'] ? req.files['jpg'][0].buffer : (keepJPG ? row.jpg : getDefaultImage());
        const name = pdfName ? pdfName : (keepPDF ? row.pdfName : "");

        // 데이터 업데이트
        const stmt = db.prepare('UPDATE reference SET title = ?, writer = ?, content = ?, pdf = ?, jpg = ?, pdfName = ? WHERE id = ?');
        stmt.run(title, writer, content, pdf, jpg, name, id, function (err) {
            if (err) {
                console.error('Error updating data in database:', err);
                res.status(500).json({ message: 'Internal server error' });
            } else {
                res.json({ message: 'Data updated successfully' });
            }
        });
        stmt.finalize();
    });
});

// 데이터 삭제
app.delete('/delete', (req, res) => {
    const id = parseInt(req.query.id, 10);

    if (isNaN(id)) {
        res.status(400).json({ message: 'Invalid ID' });
        return;
    }

    const stmt = db.prepare('DELETE FROM reference WHERE id = ?');
    stmt.run(id, function (err) {
        if (err) {
            console.error('Error deleting data from database:', err);
            res.status(500).json({ message: 'Internal server error' });
        } else if (this.changes === 0) {
            res.status(404).json({ message: 'No record found with the provided ID' });
        } else {
            res.json({ message: 'Record deleted successfully' });
        }
    });
    stmt.finalize();
});