# BitEduOA

### 食用方法

```bash
pip install -r requestment.txt
```

#### 引入与使用

```python
from bit_oa import BitOa

bit_edu_oa = BitOa("用户名", "密码")
bit_edu_oa.login()  # 返回True则登录成功, 否则退出代码 -1(可自己修改失败逻辑)
```

### 功能

- [x] 用户密码登录
- [x] 验证码检测与处理
- [x] service的处理逻辑

### 注意事项

仅供学习参考, 验证码采用 [Ddddocr](https://github.com/sml2h3/ddddocr) 库进行识别