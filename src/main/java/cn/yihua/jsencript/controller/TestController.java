package cn.yihua.jsencript.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class TestController {

    @Value("${Rsa.publicKey}")
    private String publicKey;

    @RequestMapping("/index")
    public String hello(Model model) {
        model.addAttribute("PUBLIC_KEY", publicKey);
        return "index";
    }

}