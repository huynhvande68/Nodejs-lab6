const express = require('express')
const AccountRouter = require('./routers/AccountRouter')
const app = express();
const {check,validationResult} = require('express-validator')

app.set('view engine', 'ejs')

const validator = [
    check('name').exists().withMessage('Vui lòng nhập tên người dùng')
    .notEmpty().withMessage('Không được để trống tên người dùng')
    .isLength({min: 6}).withMessage('Tên người dùng phải từ 6 kí tự'),

    check('email').exists().withMessage('Vui lòng nhập email người dùng')
    .notEmpty().withMessage('Không được để trống email người dùng')
    .isEmail().withMessage('Đây không phải là email hợp lệ'),

    check('password').exists().withMessage('Vui lòng nhập mật khẩu người dùng')
    .notEmpty().withMessage('Không được để trống mật khẩu người dùng')
    .isLength({min: 6}).withMessage('Mật khẩu người dùng phải từ 6 kí tự'),

    check('confirmPassword').exists().withMessage('Vui lòng xác nhận mật khẩu')
    .notEmpty().withMessage('Vui lòng nhập xác nhận mật khẩu')
    .custom((value, {req}) => {
        if(value !==req.body.password) {
            throw new Error('Mật khẩu không khớp');
        }
        return true;
    })
]


app.get('/', (req, res) => res.render('index'));
app.post('/register',validator ,(req,res) => {
    res.render('register');


});
app.get('/login', (req, res) => res.render('login'));
app.use('/account', AccountRouter);
app.listen(12346, () => console.log('http://localhost:12346'))