/**
 * 本文件展示 passport-local、passport-jwt 联合用法
 *   - 首次登陆，使用 passport-local 根据用户名和密码校验用户身份
 *     - 如果校验成功，签发 jwt
 *     - 如果校验失败，则反馈给前端并终止后续逻辑
 *   - 登陆成功后，后续访问前端都需要带上 jwt，passport 会解析 jwt 获取用户信息并自动调用 jwt 策略
 */

const express = require("express");
const bodyParser = require("body-parser");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const PassportJwt = require("passport-jwt");
const cookieParser = require("cookie-parser");
const Jwt = require("jsonwebtoken");
const app = express();

const secretKey = "anything you want"; // 用于签发和解析 jwt

// 用户列表
const users = [
  {
    id: 1,
    username: "chosan",
    password: "123456",
    sex: "M"
  },
  {
    id: 2,
    username: "jitian",
    password: "654321",
    sex: "F"
  }
];

// 查找用户
function findUser(value, filed = "username") {
  return users.find(user => user[filed] === value);
}

// 解析 cookie
app.use(cookieParser());
// 解析 post 请求参数
app.use(bodyParser.urlencoded({ extended: false }));
// 初始化 passport
app.use(passport.initialize());

app.get("/", (req, res) => res.sendfile("./jwt-form.html", { root: __dirname }));

// passport.authenticate("local") 表示该路由希望使用 passport-local 策略。由于校验成功我们会签发 jwt，因此无需借助 session
app.post("/login", passport.authenticate("local", { session: false }), function(req, res) {
  const { user } = req;
  const accessToken = Jwt.sign({ sub: user.id }, secretKey, { expiresIn: "1800s" });
  // 为了方便起见，我将 jwt 存放在 cookie 中，之后通过 cookieExtractor 来获取，但你也可以直接返回给前端，然后和前端约定好通过何种方式携带 jwt
  res.cookie("jwt", accessToken);
  res.json({ message: "登陆成功", accessToken });
});

// passport.authenticate("jwt") 表明我们希望该路由使用 jwt 策略，因此访问该接口需要携带 jwt，否则无法访问成功
app.get("/profile", passport.authenticate("jwt", { session: false }), (req, res) => {
  res.json(req.user);
});

app.listen(9000, () => {
  console.log("listen on 9000");
});

/****** local 策略开始 ******/

/**
 * 给 passport 添加 local 策略
 * 在使用 local 策略的路由上
 *   - passport 会自动获取获取表单中的 username 和 password 字段并调用 LocalStrategy 中的回调函数
 *   - 如果用户验证成功，则调用 done(null, user) 返回用户信息，该信息会被添加到下游函数中的 req.user 字段中
 *   - 如果用户验证失败，则调用 done(null, false)，下游函数不会再被调用
 *   - 如果系统错误，则调用 done(err)，下游函数不会再被调用
 */
passport.use(
  new LocalStrategy((username, password, done) => {
    try {
      const user = findUser(username);
      if (user.password === password) {
        done(null, user);
      } else {
        done(null, false, { message: "用户名或密码错误" });
      }
    } catch (err) {
      done(err);
    }
  })
);

/****** local 策略结束 ******/

/****** jwt 策略开始 ******/

/**
 * 给 passport 添加 jwt 策略
 * 由于 jwt 可以由客户端存放在任意位置（如 header，query string 或者 post 参数等），因此需要通过 jwtFromRequest 指定从何处获取 jwt
 * jwt 提供了一些内置的方法来获取 jwt，此处使用自定义函数 cookieExtractor 从 cookie 中获取 jwt
 * 由于在 login 中我们签发的 jwt 只包含了 user.id，因此拿到 jwt 的内容 payload 时还需要通过该 id 获取用户信息，以便下游函数使用
 */
passport.use(
  new PassportJwt.Strategy(
    {
      jwtFromRequest: cookieExtractor, // 指定从何处获取前端携带过来的 jwt
      secretOrKey: secretKey
    },
    (payload, done) => {
      const { sub: userId } = payload;
      const user = findUser(userId, "id");
      done(null, user || false);
    }
  )
);

/**
 * 从 cookie 中获取 jwt
 * @param {IncomingMessage} req 请求对象
 */
function cookieExtractor(req) {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies["jwt"];
  }
  return token;
}
/****** jwt 策略结束 ******/
