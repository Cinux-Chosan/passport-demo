/**
 * 本文件仅展示 passport-local 的用法
 */

const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const app = express();

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

// 启用 session 功能
app.use(session({ secret: "anything you want" }));
// 解析 post 请求
app.use(bodyParser.urlencoded({ extended: false }));
// 初始化 passport
app.use(passport.initialize());
// 由于本例我们只使用了 local 策略，因此让 passport 通过 session 来保持用户身份信息
app.use(passport.session());

app.get("/", (req, res) => res.sendfile("./local-form.html", { root: __dirname }));

// passport.authenticate("local") 表示该路由希望使用 passport-local 策略
app.post("/login", passport.authenticate("local"), function(req, res) {
  res.json(req.user);
});

app.listen(9000, () => {
  console.log("listen on 9000");
});

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

/**
 * serializeUser 功能：
 *   - 将用户信息序列化到 session 中保存
 *
 * tip：由于 session 存放在服务端，因此我们需要尽可能少的存放重要信息以节约存储空间和内存，此处仅将 user.id 保存到 session 中
 */
passport.serializeUser((user, done) => {
  done(null, user.id);
});

/**
 * deserializeUser 功能：
 *   - 通过 serializeUser 存储在 session 中的信息来获取用户数据，返回值会被添加到下游函数中的 req.user 中
 *
 * tip：由于我们在 serializeUser 中只保存了 user.id，因此还需要通过 id 获取用户数据
 */
passport.deserializeUser(function(id, done) {
  const user = findUser(id, "id");
  done(null, user || false);
});
