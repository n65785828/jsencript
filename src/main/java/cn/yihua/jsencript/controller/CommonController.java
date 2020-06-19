package cn.yihua.jsencript.controller;

import cn.yihua.jsencript.helper.RsaUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class CommonController {

    @Autowired
    private RsaUtils RSAUtils;

    @Value("${Rsa.publicKey}")
    private String publicKey;

    @Value("${Rsa.privateKey}")
    private String privateKey;


    @PostMapping("/encrypt")
    public String login(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        String password = request.getParameter("password");
        password = RSAUtils.decryptByPrivateKey(password,privateKey);
        return password;
    }

    @GetMapping("/encrypt")
    public String encrypt() throws Exception {
        String test = "hello world";
        test = RSAUtils.encryptByPublicKey(test, publicKey);
        test = RSAUtils.decryptByPrivateKey(test,privateKey);
        test = RSAUtils.encryptByPrivateKey(test,privateKey);
        test = RSAUtils.decryptByPublicKey(test,publicKey);
        return test;
    }
}
