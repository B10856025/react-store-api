const path = require('path');
const fs = require('fs')
const jsonServer = require('json-server');   //引入
const jwt = require('jsonwebtoken')
const server = jsonServer.create();   //create方法創建一個server
const router = jsonServer.router(path.join(__dirname, 'db.json'));   //把db.json的數據生成一個路由
const middleWares = jsonServer.defaults();   //中間鍵
server.use(jsonServer.bodyParser);   //解析器 解析發送的一些數據
server.use(middleWares);

const getUsersDb = () => {
    return JSON.parse(
        fs.readFileSync(path.join(__dirname, 'users.json'), 'UTF-8')
    );
};

const isAuthenticated = ({email, password}) => {   //找尋email和password是否被註冊過
    return (
        getUsersDb().users.findIndex(   //得到數字串
            user => user.email === email && user.password === password   //驗證是否一樣
        ) !==-1   //相等會大於1 不相等會=-1
    );
};

const isExist = ({email}) => {   //找尋email是否有一樣的
    return (
        getUsersDb().users.findIndex(   //得到數字串
            user => user.email === email   //驗證是否一樣
        ) !==-1   //相等會大於1 不相等會=-1
    );
};

//註冊jwt函數
const SECRET = '2d5f6e2set813sgr8';
const expiresIn = '1h'
const createToken = payload => {   //payload 服務端返回給客戶端的數據
    return jwt.sign(payload, SECRET, { expiresIn }  )   ///sign方法:傳遞三個參數 1.payload 2.SECRET簽名用的key 3.設置性的參數,例如時間
}

//api登入
server.post('/auth/login', (req, res) => {   
    const { email, password } = req.body;

    if (isAuthenticated({email, password})){   //校驗驗證

        const user = getUsersDb().users.find(
            u => u.email === email && u.password === password
        );
        const { nickname, type } = user;
        //jwt
        const jwToken = createToken({nickname, type, email});  //用{nickname, type, email}生成jwt
        return res.status(200).json(jwToken)
    } else {
        const status = 401;
        const message = 'Incorrect email or password';
        return res.status(status).json({ status, message })
    }
});

//api新註冊
server.post('/auth/register', (req, res) => {   
    const { nickname, email, password, type } = req.body;

    //1.查詢是否註冊過
    if (isExist({email})) {
        const status = 401;
        const message = 'Email and Password already exist';
        return res.status(status).json({ status, message });
    }

    //2.如果是新用戶就將資料寫到user.json 資料庫
    fs.readFile(path.join(__dirname, 'users.json'), (err, _data) => {//先讀取所有數據
        if (err) {   //如果讀取錯誤
            const status = 401;
            const message = err;
            return res.status(status).json({ status, message });
        }
        //讀取成功
        const data = JSON.parse(_data.toString());   //把資料解析出來
        // 拿資料的最後一個id號碼
        const last_item_id = data.users[data.users.length - 1].id;   
        //新增用戶 一個id+1獲得新id  再將資料放到data裡
        data.users.push({ id: last_item_id + 1, email, password, nickname, type });
        fs.writeFile(
            path.join(__dirname, 'users.json'),  //寫到user.json 資料庫
            JSON.stringify(data),
            (err, result) => {
                //WRITE
                if (err) {   //如果錯誤
                    const status = 401;
                    const message = err;
                    res.status(status).json({ status, message });
                    return ;
                }
            }
        );
    });

    //建立token
    const jwToken = createToken({ nickname, type, email });  //用{nickname, type, email}生成jwt
    return res.status(200).json(jwToken);
});


//通過jwt認證來獲取carts的資料保護顯示
server.use('/carts', (req, res, next) => {
    if (
        req.headers.authorization === undefined ||   //查看req的頭部資料是否有值，如果沒有值或是不是以Bearer為開頭(連接jwt)
        req.headers.authorization.split(' ')[0] !== 'Bearer'
    ) {
        const status = 401;   //失敗 401 顯示提示訊息
        const message = 'Error in authorization format';
        res.status(status).json({ status, message });
        return;
    }
    try {
        const verifyTokenResult = verifyToken(   //把jwt帶過來後看是否有效
            req.headers.authorization.split(' ')[1]
        );
        if (verifyTokenResult instanceof Error) {   //驗證錯誤
            const status = 401;
            const message = 'Access token not provided';
            res.status(status).json({ status, message });
            return;
        }
        next();   //驗證成功 調用next，處理原本的carts請求
    }   catch (err) {
        const status = 401;
        const message ='Error token is revoked';
        res.status(status).json({ status, message });
    }
});
///驗證的方法
const verifyToken = token => {
    return jwt.verify(token, SECRET, (err, decode) =>
        decode !== undefined ? decode : err
    );
};


server.use(router);
server.listen(3004, () => {   //監聽一個ˇ端口號3004
    console.log('JSON Server is running');
});