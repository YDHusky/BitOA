import random
import time

import ddddocr
import requests
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import base64
from loguru import logger
from parsel import Selector


class BitOa:
    def __init__(self, username, password, service="https://libresource.bit.edu.cn/login/self/", max_post=3):
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://login.bit.edu.cn",
            "Referer": "https://login.bit.edu.cn/authserver/login",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\""
        }
        self.max_post = max_post
        self.session = requests.Session()
        self.username = username
        self.password = password
        self.service = service

    @staticmethod
    def random_string(length=16, chars="ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"):
        return ''.join(random.choice(chars) for _ in range(length))

    @staticmethod
    def get_aes_string(n, f, c):
        f = f.strip()  # 去除两端空白字符
        f = f.encode("utf8")
        c = c.encode("utf8")
        n = n.encode("utf8")
        padded_data = pad(n, AES.block_size)  # 填充数据以满足AES块大小要求
        return base64.b64encode(AES.new(key=f, mode=AES.MODE_CBC, iv=c).encrypt(padded_data)).decode('utf-8')

    def encrypt_aes(self, n, f):
        if f:
            return self.get_aes_string(self.random_string(64) + n, f, self.random_string())
        return n

    def encrypt_password(self, password, key):
        try:
            return self.encrypt_aes(password, key)
        except Exception as e:
            logger.error(f"加密发生错误: {e}")
            return password

    def check_need_captcha(self):
        url = "https://login.bit.edu.cn/authserver/checkNeedCaptcha.htl"
        params = {
            "username": self.username,
            "_": int(time.time() * 1000),
        }
        res = self.session.get(url, params=params)
        if res.status_code != 200:
            logger.error("检测验证码失败! ")
            return True
        else:
            logger.info(f"检测验证码: {res.text}")
            return res.json()["isNeed"]

    def get_captcha(self):
        url = "https://login.bit.edu.cn/authserver/getCaptcha.htl"
        res = self.session.get(url, headers=self.headers)
        ocr = ddddocr.DdddOcr(show_ad=False)
        captcha = ocr.classification(res.content)
        logger.info(f"验证码获取成功: {captcha}")
        return captcha

    def get_login(self):
        url = "https://login.bit.edu.cn/authserver/login"
        params = {
            "service": self.service,
        }
        res = self.session.get(url, params=params, headers=self.headers)
        document = Selector(text=res.text)
        event_id = document.css("#_eventId::attr(value)").get()
        lt = document.css("#lt::attr(value)").get()
        salt = document.css("#pwdEncryptSalt::attr(value)").get()
        execution = document.css("#execution::attr(value)").get()
        data = {
            "_eventId": event_id,
            "cllt": "userNameLogin",
            "dllt": "generalLogin",
            "lt": lt,
            "captcha": "",
            "username": self.username,
            "password": self.encrypt_password(self.password, salt),
            "execution": execution
        }
        if self.check_need_captcha() is True:
            logger.info("获取验证码尝试中...")
            data["captcha"] = self.get_captcha()
        return data

    def post_login(self):
        url = "https://login.bit.edu.cn/authserver/login"
        params = {
            "service": "https://libresource.bit.edu.cn/login/self/"
        }
        data = self.get_login()
        logger.info(f"请求参数准备成功: {data}")
        response = self.session.post(url, headers=self.headers, params=params, data=data)
        if response.status_code != 200:
            document = Selector(text=response.text)
            error_info = document.css("#showErrorTip span::text").get()
            logger.error(f"登录失败: {error_info}")
            return False
        else:
            logger.success("登录成功!")
            return True

    def login(self):
        cnt = 0
        while cnt < self.max_post:
            cnt += 1
            logger.info(f"正在尝试第{cnt}次登录...")
            if self.post_login() is True:
                return True
        logger.error("登录失败, 请检查错误信息")
        exit(-1)


if __name__ == '__main__':
    test = BitOa("123456", "123456")
    test.login()
